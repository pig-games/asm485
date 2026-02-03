// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Multi-CPU Assembler - main entry point.
//!
//! This module ties together the CPU-agnostic core with CPU-specific
//! instruction encoding (8085, Z80).

pub mod cli;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Parser;

use crate::core::assembler::conditional::{
    ConditionalBlockKind, ConditionalContext, ConditionalStack,
};
use crate::core::assembler::error::{
    AsmError, AsmErrorKind, AsmRunError, AsmRunReport, Diagnostic, LineStatus, PassCounts, Severity,
};
use crate::core::assembler::expression::{
    apply_assignment_op, eval_binary_op, eval_unary_op, expr_span, parse_number_text, AstEvalError,
};
use crate::core::assembler::listing::{ListingLine, ListingWriter};
use crate::core::assembler::scope::ScopeStack;
use crate::core::cpu::CpuType;
use crate::core::family::{AssemblerContext, EncodeResult};
use crate::core::imagestore::ImageStore;
use crate::core::macro_processor::MacroProcessor;
use crate::core::parser as asm_parser;
use crate::core::parser::{AssignOp, Expr, Label, LineAst, ParseError};
use crate::core::preprocess::Preprocessor;
use crate::core::registry::{ModuleRegistry, RegistryError};
use crate::core::symbol_table::{ImportResult, ModuleImport, SymbolTable, SymbolVisibility};
use crate::core::token_value::TokenValue;
use crate::core::tokenizer::{register_checker_none, ConditionalKind, Span};
use std::sync::Arc;

use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::z80::module::Z80CpuModule;

use cli::{
    input_base_from_path, resolve_bin_path, resolve_output_path, validate_cli, BinOutputSpec, Cli,
};

// Re-export public types
pub use crate::core::assembler::error::{AsmRunError as RunError, AsmRunReport as RunReport};
pub use cli::VERSION;

const DEFAULT_MODULE_EXTENSIONS: &[&str] = &["asm", "inc"];

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
        let report = run_one(
            &cli,
            &asm_name,
            &input_base,
            config.out_dir.as_ref(),
            &config.bin_specs,
            config.go_addr.as_deref(),
            config.fill_byte,
            config.fill_byte_set,
            config.pp_macro_depth,
            config.default_outputs,
        )?;
        reports.push(report);
    }

    Ok(reports)
}

#[derive(Debug, Clone)]
struct ModuleFileInfo {
    path: PathBuf,
    has_explicit_modules: bool,
}

#[derive(Debug, Default)]
struct ModuleIndex {
    modules: HashMap<String, Vec<ModuleFileInfo>>,
}

struct ModuleLoadContext<'a> {
    index: &'a ModuleIndex,
    loaded: &'a mut HashSet<String>,
    preloaded: &'a HashSet<String>,
    order: &'a mut Vec<Vec<String>>,
    stack: &'a mut Vec<String>,
    defines: &'a [String],
    pp_macro_depth: usize,
}

#[derive(Debug, Default, Clone)]
struct OutputConfig {
    name: Option<String>,
    list_name: Option<String>,
    hex_name: Option<String>,
    bin_specs: Vec<BinOutputSpec>,
    fill_byte: Option<u8>,
}

impl OutputConfig {
    fn merge_override(&self, override_cfg: Option<&OutputConfig>) -> OutputConfig {
        let mut merged = self.clone();
        let Some(override_cfg) = override_cfg else {
            return merged;
        };
        if override_cfg.name.is_some() {
            merged.name = override_cfg.name.clone();
        }
        if override_cfg.list_name.is_some() {
            merged.list_name = override_cfg.list_name.clone();
        }
        if override_cfg.hex_name.is_some() {
            merged.hex_name = override_cfg.hex_name.clone();
        }
        if !override_cfg.bin_specs.is_empty() {
            merged.bin_specs = override_cfg.bin_specs.clone();
        }
        if override_cfg.fill_byte.is_some() {
            merged.fill_byte = override_cfg.fill_byte;
        }
        merged
    }
}

#[derive(Debug, Default, Clone)]
struct RootMetadata {
    root_module_id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    output_default: OutputConfig,
    output_by_target: HashMap<String, OutputConfig>,
}

#[derive(Debug, Default, Clone)]
struct SectionState {
    pc: u16,
    bytes: Vec<u8>,
    placed: bool,
}

impl RootMetadata {
    fn output_config_for_cpu(&self, cpu_name: &str) -> OutputConfig {
        let key = cpu_name.to_ascii_lowercase();
        let override_cfg = self.output_by_target.get(&key);
        self.output_default.merge_override(override_cfg)
    }

    fn output_config_mut(&mut self, target: Option<&str>) -> &mut OutputConfig {
        if let Some(target) = target {
            let key = target.to_ascii_lowercase();
            return self.output_by_target.entry(key).or_default();
        }
        &mut self.output_default
    }
}

fn canonical_module_id(module_id: &str) -> String {
    module_id.to_ascii_lowercase()
}

fn module_id_from_path(path: &Path) -> Result<String, AsmRunError> {
    let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Cli, "Invalid module filename", None),
            Vec::new(),
            Vec::new(),
        )
    })?;
    Ok(stem.to_string())
}

fn root_module_id_from_lines(
    root_path: &Path,
    root_lines: &[String],
) -> Result<String, AsmRunError> {
    let explicit = scan_module_ids(root_lines);
    if explicit.is_empty() {
        return module_id_from_path(root_path);
    }
    let implicit = module_id_from_path(root_path)?;
    if let Some(matched) = explicit
        .iter()
        .find(|module_id| module_id.eq_ignore_ascii_case(&implicit))
    {
        return Ok(matched.clone());
    }
    Ok(explicit[0].clone())
}

fn resolve_output_base(
    cli: &Cli,
    input_base: &str,
    out_dir: Option<&PathBuf>,
    metadata: &RootMetadata,
    cpu: CpuType,
) -> String {
    let output_config = metadata.output_config_for_cpu(cpu.as_str());
    let mut base = if out_dir.is_some() {
        input_base.to_string()
    } else if let Some(outfile) = cli.outfile.as_deref() {
        outfile.to_string()
    } else if let Some(output) = output_config.name.as_deref() {
        output.to_string()
    } else {
        input_base.to_string()
    };

    if let Some(dir) = out_dir {
        base = dir.join(base).to_string_lossy().to_string();
    }

    base
}

fn expand_source_file(
    path: &Path,
    defines: &[String],
    pp_macro_depth: usize,
) -> Result<Vec<String>, AsmRunError> {
    let mut pp = Preprocessor::with_max_depth(pp_macro_depth);
    for def in defines {
        if let Some((name, value)) = def.split_once('=') {
            pp.define(name, value);
        } else {
            pp.define(def, "1");
        }
    }
    if let Err(err) = pp.process_file(path.to_string_lossy().as_ref()) {
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
    Ok(expanded_lines)
}

fn parse_line_ast(line: &str, line_num: u32) -> Option<LineAst> {
    let mut parser = asm_parser::Parser::from_line(line, line_num).ok()?;
    parser.parse_line().ok()
}

fn expr_to_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(name, _) | Expr::Register(name, _) => Some(name.clone()),
        _ => None,
    }
}

fn scan_module_ids(lines: &[String]) -> Vec<String> {
    let mut modules = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(LineAst::Statement {
            mnemonic, operands, ..
        }) = parse_line_ast(line, idx as u32 + 1)
        else {
            continue;
        };
        let Some(mnemonic) = mnemonic else { continue };
        if !mnemonic.eq_ignore_ascii_case(".module") {
            continue;
        }
        if let Some(expr) = operands.first() {
            if let Some(name) = expr_to_ident(expr) {
                modules.push(name);
            }
        }
    }
    modules
}

fn collect_use_directives(lines: &[String]) -> Vec<String> {
    let mut uses = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(ast) = parse_line_ast(line, idx as u32 + 1) else {
            continue;
        };
        if let LineAst::Use { module_id, .. } = ast {
            uses.push(module_id);
        }
    }
    uses
}

fn extract_module_block(lines: &[String], module_id: &str) -> Option<Vec<String>> {
    let mut captured = Vec::new();
    let mut capture = false;
    let mut depth = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        let Some(LineAst::Statement {
            mnemonic, operands, ..
        }) = parse_line_ast(line, idx as u32 + 1)
        else {
            if capture {
                captured.push(line.clone());
            }
            continue;
        };
        let Some(mnemonic) = mnemonic else {
            if capture {
                captured.push(line.clone());
            }
            continue;
        };
        if mnemonic.eq_ignore_ascii_case(".module") {
            if let Some(expr) = operands.first() {
                if let Some(name) = expr_to_ident(expr) {
                    if name.eq_ignore_ascii_case(module_id) {
                        capture = true;
                        depth = 1;
                        captured.push(line.clone());
                        continue;
                    }
                }
            }
        }
        if mnemonic.eq_ignore_ascii_case(".endmodule") && capture {
            captured.push(line.clone());
            depth = depth.saturating_sub(1);
            if depth == 0 {
                break;
            }
            continue;
        }
        if capture {
            captured.push(line.clone());
        }
    }
    if capture {
        Some(captured)
    } else {
        None
    }
}

fn collect_source_files(root: &Path, extensions: &[&str]) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(ext))
            {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn build_module_index(root: &Path) -> Result<ModuleIndex, AsmRunError> {
    let files = collect_source_files(root, DEFAULT_MODULE_EXTENSIONS).map_err(|err| {
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, "Error reading module roots", None),
            vec![],
            vec![err.to_string()],
        )
    })?;

    let mut index = ModuleIndex::default();
    for path in files {
        let contents = fs::read_to_string(&path).map_err(|err| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, "Error reading module source", None),
                vec![],
                vec![err.to_string()],
            )
        })?;
        let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
        let explicit_modules = scan_module_ids(&lines);
        if explicit_modules.is_empty() {
            let implicit_id = module_id_from_path(&path)?;
            let canonical = canonical_module_id(&implicit_id);
            index
                .modules
                .entry(canonical)
                .or_default()
                .push(ModuleFileInfo {
                    path,
                    has_explicit_modules: false,
                });
            continue;
        }
        for module_id in explicit_modules {
            let canonical = canonical_module_id(&module_id);
            index
                .modules
                .entry(canonical)
                .or_default()
                .push(ModuleFileInfo {
                    path: path.clone(),
                    has_explicit_modules: true,
                });
        }
    }
    Ok(index)
}

fn load_module_recursive(
    module_id: &str,
    ctx: &mut ModuleLoadContext<'_>,
) -> Result<(), AsmRunError> {
    let canonical = canonical_module_id(module_id);
    if ctx.loaded.contains(&canonical) || ctx.preloaded.contains(&canonical) {
        return Ok(());
    }
    let infos = ctx.index.modules.get(&canonical).ok_or_else(|| {
        let mut message = format!("Missing module: {module_id}");
        if !ctx.stack.is_empty() {
            let chain = ctx.stack.join(" -> ");
            message.push_str(&format!(" (import stack: {chain})"));
        }
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Directive, &message, None),
            vec![],
            vec![],
        )
    })?;
    if infos.len() > 1 {
        let mut message = format!("Ambiguous module: {module_id}");
        if !ctx.stack.is_empty() {
            let chain = ctx.stack.join(" -> ");
            message.push_str(&format!(" (import stack: {chain})"));
        }
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Directive, &message, None),
            vec![],
            vec![],
        ));
    }
    let info = &infos[0];

    ctx.stack.push(module_id.to_string());
    let expanded_lines = expand_source_file(&info.path, ctx.defines, ctx.pp_macro_depth)?;
    let module_lines = if info.has_explicit_modules {
        extract_module_block(&expanded_lines, module_id).ok_or_else(|| {
            AsmRunError::new(
                AsmError::new(
                    AsmErrorKind::Directive,
                    "Module not found in source",
                    Some(module_id),
                ),
                vec![],
                vec![],
            )
        })?
    } else {
        expanded_lines
    };

    for dep in collect_use_directives(&module_lines) {
        load_module_recursive(&dep, ctx)?;
    }

    ctx.loaded.insert(canonical);
    ctx.order.push(module_lines);
    ctx.stack.pop();
    Ok(())
}

fn load_module_graph(
    root_path: &Path,
    root_lines: Vec<String>,
    defines: &[String],
    pp_macro_depth: usize,
) -> Result<Vec<String>, AsmRunError> {
    let root_dir = root_path
        .parent()
        .ok_or_else(|| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Cli, "Invalid input path", None),
                vec![],
                vec![],
            )
        })?
        .to_path_buf();
    let index = build_module_index(&root_dir)?;

    let mut preloaded = HashSet::new();
    let mut explicit_modules = scan_module_ids(&root_lines);
    if explicit_modules.is_empty() {
        explicit_modules.push(module_id_from_path(root_path)?);
    }
    for module_id in explicit_modules {
        preloaded.insert(canonical_module_id(&module_id));
    }

    let mut loaded = HashSet::new();
    let mut order = Vec::new();
    let mut stack = Vec::new();
    let mut ctx = ModuleLoadContext {
        index: &index,
        loaded: &mut loaded,
        preloaded: &preloaded,
        order: &mut order,
        stack: &mut stack,
        defines,
        pp_macro_depth,
    };
    for dep in collect_use_directives(&root_lines) {
        load_module_recursive(&dep, &mut ctx)?;
    }

    let mut combined = Vec::new();
    for module_lines in order {
        combined.extend(module_lines);
    }
    combined.extend(root_lines);
    Ok(combined)
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    cli: &Cli,
    asm_name: &str,
    input_base: &str,
    out_dir: Option<&PathBuf>,
    bin_specs: &[BinOutputSpec],
    go_addr: Option<&str>,
    fill_byte: u8,
    fill_byte_set: bool,
    pp_macro_depth: usize,
    default_outputs: bool,
) -> Result<AsmRunReport, AsmRunError> {
    let root_path = Path::new(asm_name);
    let root_lines = expand_source_file(root_path, &cli.defines, pp_macro_depth)?;
    let root_module_id = root_module_id_from_lines(root_path, &root_lines)?;
    let expanded_lines = load_module_graph(root_path, root_lines, &cli.defines, pp_macro_depth)?;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some(root_module_id);
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

    let output_config = assembler
        .root_metadata
        .output_config_for_cpu(assembler.cpu().as_str());
    let metadata_output = output_config.name.as_deref();
    let meta_outputs_requested = output_config.list_name.is_some()
        || output_config.hex_name.is_some()
        || !output_config.bin_specs.is_empty();
    let effective_default_outputs = default_outputs && !meta_outputs_requested;
    if effective_default_outputs && metadata_output.is_none() && cli.outfile.is_none() {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "No outputs selected. Provide .meta.output.name (or -o) or specify output flags",
                None,
            ),
            Vec::new(),
            expanded_lines.clone(),
        ));
    }

    let out_base = resolve_output_base(
        cli,
        input_base,
        out_dir,
        &assembler.root_metadata,
        assembler.cpu(),
    );
    let list_name = if cli.list_name.is_some() {
        cli.list_name.clone()
    } else {
        output_config.list_name.clone()
    };
    let list_path = match list_name {
        Some(name) => resolve_output_path(&out_base, Some(name), "lst"),
        None if effective_default_outputs => {
            resolve_output_path(&out_base, Some(String::new()), "lst")
        }
        None => None,
    };
    let hex_name = if cli.hex_name.is_some() {
        cli.hex_name.clone()
    } else {
        output_config.hex_name.clone()
    };
    let hex_path = match hex_name {
        Some(name) => resolve_output_path(&out_base, Some(name), "hex"),
        None if effective_default_outputs => {
            resolve_output_path(&out_base, Some(String::new()), "hex")
        }
        None => None,
    };
    if go_addr.is_some() && hex_path.is_none() {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "-g/--go requires hex output (-x/--hex or output metadata)",
                None,
            ),
            Vec::new(),
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
                AsmError::new(
                    AsmErrorKind::Io,
                    "Error opening file for write",
                    Some(hex_path),
                ),
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

    let effective_bin_specs = if !bin_specs.is_empty() {
        bin_specs.to_vec()
    } else {
        output_config.bin_specs.clone()
    };
    let effective_fill_byte = if fill_byte_set {
        fill_byte
    } else {
        output_config.fill_byte.unwrap_or(fill_byte)
    };
    if fill_byte_set && effective_bin_specs.is_empty() {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "-f/--fill requires binary output (-b/--bin or output metadata)",
                None,
            ),
            Vec::new(),
            expanded_lines.clone(),
        ));
    }
    let mut bin_outputs = Vec::new();
    let bin_count = effective_bin_specs.len();
    for spec in &effective_bin_specs {
        let bin_name = resolve_bin_path(&out_base, spec.name.as_deref(), &spec.range, bin_count);
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
        if let Err(err) = assembler.image().write_bin_file(
            &mut bin_file,
            range.start,
            range.end,
            effective_fill_byte,
        ) {
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
    root_metadata: RootMetadata,
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
            root_metadata: RootMetadata::default(),
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
        let mut addr: u16 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;

        {
            let root_metadata = std::mem::take(&mut self.root_metadata);
            let mut asm_line = AsmLine::with_cpu_and_metadata(
                &mut self.symbols,
                self.cpu,
                &self.registry,
                root_metadata,
            );
            asm_line.clear_conditionals();
            asm_line.clear_scopes();

            for src in lines {
                let line_addr = asm_line.current_addr(addr);
                let status = asm_line.process(src, line_num, line_addr, 1);
                if status == LineStatus::Pass1Error {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                    }
                    counts.errors += 1;
                } else {
                    asm_line.update_addresses(&mut addr, status);
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

            self.root_metadata = asm_line.take_root_metadata();
        }

        for issue in self.symbols.validate_imports() {
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
            let line_addr = asm_line.current_addr(addr);
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

            asm_line.update_addresses(&mut addr, status);
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

        counts.lines = line_num - 1;
        Ok(counts)
    }
}

/// Per-line assembler state.
struct AsmLine<'a> {
    symbols: &'a mut SymbolTable,
    registry: &'a ModuleRegistry,
    root_metadata: RootMetadata,
    cond_stack: ConditionalStack,
    scope_stack: ScopeStack,
    visibility_stack: Vec<SymbolVisibility>,
    module_active: Option<String>,
    module_scope_depth: usize,
    in_meta_block: bool,
    in_output_block: bool,
    output_cpu_block: Option<String>,
    sections: HashMap<String, SectionState>,
    section_stack: Vec<Option<String>>,
    current_section: Option<String>,
    saw_explicit_module: bool,
    top_level_content_seen: bool,
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
        Self::with_cpu_and_metadata(symbols, cpu, registry, RootMetadata::default())
    }

    fn with_cpu_and_metadata(
        symbols: &'a mut SymbolTable,
        cpu: CpuType,
        registry: &'a ModuleRegistry,
        root_metadata: RootMetadata,
    ) -> Self {
        Self {
            symbols,
            registry,
            root_metadata,
            cond_stack: ConditionalStack::new(),
            scope_stack: ScopeStack::new(),
            visibility_stack: vec![SymbolVisibility::Private],
            module_active: None,
            module_scope_depth: 0,
            in_meta_block: false,
            in_output_block: false,
            output_cpu_block: None,
            sections: HashMap::new(),
            section_stack: Vec::new(),
            current_section: None,
            saw_explicit_module: false,
            top_level_content_seen: false,
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

    fn take_root_metadata(&mut self) -> RootMetadata {
        std::mem::take(&mut self.root_metadata)
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
        self.visibility_stack.clear();
        self.visibility_stack.push(SymbolVisibility::Private);
        self.module_active = None;
        self.module_scope_depth = 0;
        self.in_meta_block = false;
        self.in_output_block = false;
        self.output_cpu_block = None;
        self.sections.clear();
        self.section_stack.clear();
        self.current_section = None;
        self.saw_explicit_module = false;
        self.top_level_content_seen = false;
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

    fn in_module(&self) -> bool {
        self.module_active.is_some()
    }

    fn in_section(&self) -> bool {
        self.current_section.is_some()
    }

    fn current_section_name(&self) -> Option<&str> {
        self.current_section.as_deref()
    }

    fn current_addr(&self, main_addr: u16) -> u16 {
        match self.current_section.as_deref() {
            Some(name) => self
                .sections
                .get(name)
                .map(|section| section.pc)
                .unwrap_or(main_addr),
            None => main_addr,
        }
    }

    fn update_addresses(&mut self, main_addr: &mut u16, status: LineStatus) {
        let num_bytes = self.num_bytes() as u16;
        if let Some(section_name) = self.current_section.clone() {
            if let Some(section) = self.sections.get_mut(&section_name) {
                if self.pass == 2 {
                    if status == LineStatus::DirDs && self.aux_value > 0 {
                        section
                            .bytes
                            .extend(std::iter::repeat_n(0, self.aux_value as usize));
                    } else if status == LineStatus::DirEqu && self.start_addr > section.pc {
                        let pad = self.start_addr.wrapping_sub(section.pc) as usize;
                        section.bytes.extend(std::iter::repeat_n(0, pad));
                    } else if !self.bytes.is_empty() {
                        section.bytes.extend_from_slice(&self.bytes);
                    }
                }
                if status == LineStatus::DirDs {
                    section.pc = section.pc.wrapping_add(self.aux_value);
                } else if status == LineStatus::DirEqu {
                    section.pc = self.start_addr;
                } else {
                    section.pc = section.pc.wrapping_add(num_bytes);
                }
            }
        } else if status == LineStatus::DirDs {
            *main_addr = main_addr.wrapping_add(self.aux_value);
        } else if status == LineStatus::DirEqu {
            *main_addr = self.start_addr;
        } else {
            *main_addr = main_addr.wrapping_add(num_bytes);
        }
    }

    fn is_allowed_meta_directive(&self, mnemonic: &str) -> bool {
        if self.in_output_block {
            return is_output_block_directive(mnemonic)
                || self.is_output_cpu_block_directive(mnemonic);
        }
        is_meta_block_directive(mnemonic)
    }

    fn is_output_cpu_block_directive(&self, mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        if let Some(name) = upper.strip_prefix(".END") {
            return self.registry.resolve_cpu_name(name).is_some();
        }
        if let Some(name) = upper.strip_prefix('.') {
            return self.registry.resolve_cpu_name(name).is_some();
        }
        false
    }

    fn current_visibility(&self) -> SymbolVisibility {
        self.visibility_stack
            .last()
            .copied()
            .unwrap_or(SymbolVisibility::Private)
    }

    fn push_visibility(&mut self) {
        let current = self.current_visibility();
        self.visibility_stack.push(current);
    }

    fn pop_visibility(&mut self) -> bool {
        if self.visibility_stack.len() > 1 {
            self.visibility_stack.pop();
            true
        } else {
            false
        }
    }

    fn set_visibility(&mut self, visibility: SymbolVisibility) {
        if let Some(current) = self.visibility_stack.last_mut() {
            *current = visibility;
        } else {
            self.visibility_stack.push(visibility);
        }
    }

    fn ast_is_toplevel_directive(ast: &LineAst) -> bool {
        match ast {
            LineAst::Statement {
                mnemonic: Some(mnemonic),
                ..
            } => is_toplevel_directive(mnemonic),
            _ => false,
        }
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

    fn resolve_imported_name(&self, name: &str) -> Option<String> {
        let module_id = self.module_active.as_deref()?;
        let (target_module, target_name) =
            self.symbols.resolve_selective_import(module_id, name)?;
        Some(format!("{target_module}.{target_name}"))
    }

    fn resolve_import_alias(&self, name: &str) -> Option<String> {
        let module_id = self.module_active.as_deref()?;
        let (prefix, rest) = name.split_once('.')?;
        let target_module = self.symbols.resolve_import_alias(module_id, prefix)?;
        Some(format!("{target_module}.{rest}"))
    }

    fn selective_import_conflict(&self, name: &str) -> bool {
        if name.contains('.') {
            return false;
        }
        let module_id = match self.module_active.as_deref() {
            Some(module_id) => module_id,
            None => return false,
        };
        if self.scope_stack.depth() != self.module_scope_depth {
            return false;
        }
        self.symbols
            .resolve_selective_import(module_id, name)
            .is_some()
    }

    fn resolve_scoped_name(&self, name: &str) -> Result<Option<String>, AsmError> {
        if name.contains('.') {
            let candidate = self
                .resolve_import_alias(name)
                .unwrap_or_else(|| name.to_string());
            if let Some(entry) = self.symbols.entry(&candidate) {
                if !self.entry_is_visible(entry) {
                    return Err(self.visibility_error(name));
                }
                return Ok(Some(candidate));
            }
            return Ok(None);
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if let Some(entry) = self.symbols.entry(&candidate) {
                if !self.entry_is_visible(entry) {
                    return Err(self.visibility_error(name));
                }
                return Ok(Some(candidate));
            }
            depth = depth.saturating_sub(1);
        }
        if let Some(entry) = self.symbols.entry(name) {
            if !self.entry_is_visible(entry) {
                return Err(self.visibility_error(name));
            }
            Ok(Some(name.to_string()))
        } else if let Some(imported) = self.resolve_imported_name(name) {
            if let Some(entry) = self.symbols.entry(&imported) {
                if !self.entry_is_visible(entry) {
                    return Err(self.visibility_error(name));
                }
                Ok(Some(imported))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn lookup_scoped_entry(
        &self,
        name: &str,
    ) -> Option<&crate::core::symbol_table::SymbolTableEntry> {
        if name.contains('.') {
            let candidate = self
                .resolve_import_alias(name)
                .unwrap_or_else(|| name.to_string());
            return self.symbols.entry(&candidate);
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if let Some(entry) = self.symbols.entry(&candidate) {
                return Some(entry);
            }
            depth = depth.saturating_sub(1);
        }
        if let Some(entry) = self.symbols.entry(name) {
            return Some(entry);
        }
        if let Some(imported) = self.resolve_imported_name(name) {
            return self.symbols.entry(&imported);
        }
        None
    }

    fn entry_is_visible(&self, entry: &crate::core::symbol_table::SymbolTableEntry) -> bool {
        match entry.visibility {
            SymbolVisibility::Public => true,
            SymbolVisibility::Private => match (&entry.module_id, &self.module_active) {
                (Some(entry_module), Some(current_module)) => {
                    entry_module.eq_ignore_ascii_case(current_module)
                }
                (Some(_), None) => false,
                (None, _) => true,
            },
        }
    }

    fn visibility_error(&self, name: &str) -> AsmError {
        AsmError::new(AsmErrorKind::Symbol, "Symbol is private", Some(name))
    }

    fn process(&mut self, line: &str, line_num: u32, addr: u16, pass: u8) -> LineStatus {
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
                Arc::new(move |ident: &str| family.is_register(ident) || family.is_condition(ident))
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
                LineAst::StatementDef { span, .. } => self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Parser,
                    "Nested .statement definitions are not supported",
                    None,
                    span,
                ),
                _ => LineStatus::Skip,
            };
        }

        if !self.in_module() {
            if self.saw_explicit_module {
                if !matches!(ast, LineAst::Empty) && !Self::ast_is_toplevel_directive(&ast) {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Top-level content must be inside a .module block",
                        None,
                    );
                }
            } else if !matches!(ast, LineAst::Empty) && !Self::ast_is_toplevel_directive(&ast) {
                self.top_level_content_seen = true;
            }
        }

        if self.in_meta_block && !self.cond_stack.skipping() {
            match &ast {
                LineAst::Empty | LineAst::Conditional { .. } => {}
                LineAst::Statement {
                    label, mnemonic, ..
                } => {
                    if label.is_some() {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Labels are not allowed inside a .meta block",
                            None,
                        );
                    }
                    match mnemonic.as_deref() {
                        Some(name) if self.is_allowed_meta_directive(name) => {}
                        Some(_) | None => {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Only metadata directives are allowed inside a .meta block",
                                None,
                            );
                        }
                    }
                }
                _ => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Only metadata directives are allowed inside a .meta block",
                        None,
                    );
                }
            }
        }
        match ast {
            LineAst::Empty => LineStatus::NothingDone,
            LineAst::Conditional { kind, exprs, span } => {
                self.process_conditional_ast(kind, &exprs, span)
            }
            LineAst::Use {
                module_id,
                alias,
                items,
                params,
                span,
            } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                if !self.in_module() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".use must appear inside a module",
                        None,
                        span,
                    );
                }
                if self.scope_stack.depth() != self.module_scope_depth {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".use must appear at module scope",
                        None,
                        span,
                    );
                }
                if self.pass == 1 {
                    let import = ModuleImport {
                        module_id,
                        alias,
                        items,
                        params,
                        span,
                    };
                    let module_name = self.module_active.as_deref().expect("module active");
                    match self.symbols.add_import(module_name, import) {
                        ImportResult::Ok => LineStatus::Ok,
                        ImportResult::AliasCollision => self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Import alias already in use",
                            None,
                            span,
                        ),
                        ImportResult::SelectiveCollision => self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Selective import name already in use",
                            None,
                            span,
                        ),
                    }
                } else {
                    LineStatus::Ok
                }
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
            LineAst::Assignment {
                label,
                op,
                expr,
                span,
            } => {
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
                            if self.pass == 1 && self.selective_import_conflict(&label.name) {
                                return self.failure_at_span(
                                    LineStatus::Error,
                                    AsmErrorKind::Symbol,
                                    "Symbol conflicts with selective import",
                                    Some(&label.name),
                                    label.span,
                                );
                            }
                            let full_name = self.scoped_define_name(&label.name);
                            let res = if self.pass == 1 {
                                self.symbols.add(
                                    &full_name,
                                    self.start_addr as u32,
                                    false,
                                    self.current_visibility(),
                                    self.module_active.as_deref(),
                                )
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
                        if self.pass == 1 && self.selective_import_conflict(&label.name) {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Symbol,
                                "Symbol conflicts with selective import",
                                Some(&label.name),
                                label.span,
                            );
                        }
                        let full_name = self.scoped_define_name(&label.name);
                        let res = if self.pass == 1 {
                            self.symbols.add(
                                &full_name,
                                self.start_addr as u32,
                                false,
                                self.current_visibility(),
                                self.module_active.as_deref(),
                            )
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
                if !self.in_meta_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".output is only allowed inside a .meta block",
                        None,
                    );
                }
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
                LineStatus::Ok
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
            "DSECTION" => {
                if self.in_section() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".dsection is not allowed inside a .section block",
                        None,
                    );
                }
                if operands.len() != 1 {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Missing section name for .dsection",
                        None,
                    );
                }
                let Some(name) = operands.first().and_then(expr_to_ident) else {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid section name for .dsection",
                        None,
                    );
                };
                let section = self.sections.entry(name.clone()).or_default();
                if section.placed {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section already placed",
                        Some(&name),
                    );
                }
                section.placed = true;
                if self.pass == 2 {
                    self.bytes = section.bytes.clone();
                } else {
                    self.bytes = vec![0u8; section.pc as usize];
                }
                LineStatus::Ok
            }
            "SECTION" => {
                if operands.len() != 1 {
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
                if let Some(section) = self.sections.get(&name) {
                    if section.placed {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section has already been placed",
                            Some(&name),
                        );
                    }
                } else {
                    self.sections.insert(name.clone(), SectionState::default());
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
            "LIST" | "HEX" | "BIN" | "FILL" => {
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
                if let Some(section_name) = self.current_section.as_deref() {
                    if let Some(section) = self.sections.get(section_name) {
                        if val < section.pc as u32 {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                ".org cannot move backwards inside a section",
                                None,
                            );
                        }
                    }
                }
                self.start_addr = val as u16;
                self.aux_value = val as u16;
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
                let align = val as u16;
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
                self.aux_value = val as u16;
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
        let value = self.metadata_value(operands, directive)?;
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
                if self.pass == 1 && self.selective_import_conflict(&label.name) {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "Symbol conflicts with selective import",
                        Some(&label.name),
                        label.span,
                    );
                }
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
            Ok(Some(name)) => name,
            Ok(None) => {
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Symbol,
                    "symbol has not been defined",
                    Some(&label.name),
                    Some(1),
                )
            }
            Err(err) => {
                return self.failure_at(
                    LineStatus::Error,
                    err.kind(),
                    err.message(),
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

        let resolved_operands =
            match pipeline
                .cpu
                .resolve_operands(mnemonic, mapped_operands.as_ref(), self)
            {
                Ok(ops) => ops,
                Err(err) => {
                    return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &err, None)
                }
            };

        if let Some(validator) = pipeline.validator.as_ref() {
            if let Err(err) =
                validator.validate_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
            {
                return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &err, None);
            }
        }

        match pipeline
            .family
            .encode_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
        {
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
                    self.failure(LineStatus::Error, AsmErrorKind::Instruction, &msg, None)
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
                        self.failure(LineStatus::Error, AsmErrorKind::Instruction, &msg, None)
                    }
                }
                EncodeResult::NotFound => self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &format!("No instruction found for {}", mnemonic.to_ascii_uppercase()),
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
        ".BLOCK"
            | ".ENDBLOCK"
            | ".MODULE"
            | ".ENDMODULE"
            | ".META"
            | ".ENDMETA"
            | ".SECTION"
            | ".ENDSECTION"
    )
}

fn is_meta_block_directive(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        ".META" | ".NAME" | ".VERSION" | ".OUTPUT" | ".ENDOUTPUT" | ".ENDMETA"
    ) || upper.starts_with(".OUTPUT.")
}

fn is_output_block_directive(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        ".NAME" | ".LIST" | ".HEX" | ".BIN" | ".FILL" | ".OUTPUT" | ".ENDOUTPUT"
    ) || upper.starts_with(".OUTPUT.")
}

fn is_toplevel_directive(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        ".MODULE" | ".ENDMODULE" | ".END"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        expand_source_file, load_module_graph, root_module_id_from_lines, AsmErrorKind, AsmLine,
        Assembler, LineStatus, ListingWriter, RootMetadata, Severity,
    };
    use crate::core::macro_processor::MacroProcessor;
    use crate::core::registry::ModuleRegistry;
    use crate::core::symbol_table::SymbolTable;
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::i8085::module::{I8085CpuModule, CPU_ID as i8085_cpu_id};
    use crate::m65c02::module::M65C02CpuModule;
    use crate::z80::module::{Z80CpuModule, CPU_ID as z80_cpu_id};
    use std::fs::{self, File};
    use std::io;
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

    fn process_line(asm: &mut AsmLine<'_>, line: &str, addr: u16, pass: u8) -> LineStatus {
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
        let base = asm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Invalid example filename".to_string())?;

        assemble_example_with_base(asm_path, out_dir, base)
    }

    fn assemble_example_with_base(
        asm_path: &Path,
        out_dir: &Path,
        base: &str,
    ) -> Result<(), String> {
        let list_path = out_dir.join(format!("{base}.lst"));
        let hex_path = out_dir.join(format!("{base}.hex"));

        let mut list_file =
            File::create(&list_path).map_err(|err| format!("Create list file: {err}"))?;
        let mut hex_file =
            File::create(&hex_path).map_err(|err| format!("Create hex file: {err}"))?;

        let root_path = asm_path;
        let root_lines = expand_source_file(root_path, &[], 64)
            .map_err(|err| format!("Preprocess failed: {err}"))?;
        let expanded_lines = load_module_graph(root_path, root_lines.clone(), &[], 64)
            .map_err(|err| format!("Preprocess failed: {err}"))?;

        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id =
            Some(root_module_id_from_lines(root_path, &root_lines).map_err(|err| err.to_string())?);
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

    fn run_pass1(lines: &[&str]) -> Assembler {
        let mut assembler = Assembler::new();
        let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
        let _ = assembler.pass1(&lines);
        assembler
    }

    fn create_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("test-{label}-{}-{nanos}", process::id()));
        fs::create_dir_all(&dir).expect("Create temp dir");
        dir
    }

    fn write_file(path: &Path, contents: &str) {
        fs::write(path, contents).expect("Write test file");
    }

    fn assemble_example_error(asm_path: &Path) -> Option<String> {
        let asm_name = asm_path.to_string_lossy().to_string();

        let root_path = Path::new(&asm_name);
        let root_lines = match expand_source_file(root_path, &[], 64) {
            Ok(lines) => lines,
            Err(err) => return Some(format!("Preprocess failed: {err}")),
        };
        let expanded_lines = match load_module_graph(root_path, root_lines.clone(), &[], 64) {
            Ok(lines) => lines,
            Err(err) => return Some(format!("Preprocess failed: {err}")),
        };

        let mut assembler = Assembler::new();
        if let Ok(module_id) = root_module_id_from_lines(root_path, &root_lines) {
            assembler.root_metadata.root_module_id = Some(module_id);
        }
        assembler.clear_diagnostics();
        let _ = assembler.pass1(&expanded_lines);

        let mut sink = io::sink();
        let mut listing = ListingWriter::new(&mut sink, false);
        if listing.header("opForge 8085 Assembler v1.0").is_ok() {
            let _ = assembler.pass2(&expanded_lines, &mut listing);
        }

        assembler
            .diagnostics
            .iter()
            .find(|diag| diag.severity == Severity::Error)
            .map(|diag| format!("Assembly failed: {}", diag.error.message()))
    }

    #[test]
    fn module_loader_orders_dependencies_before_root() {
        let dir = create_temp_dir("module-order");
        let root_path = dir.join("main.asm");
        let lib_path = dir.join("lib.asm");

        write_file(
            &root_path,
            ".module app\n    .use lib\n    .byte 1\n.endmodule\n",
        );
        write_file(
            &lib_path,
            ".module lib\n    .pub\nVAL .const 2\n.endmodule\n",
        );

        let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
        let combined = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");

        let lib_idx = combined
            .iter()
            .position(|line| line.trim().eq_ignore_ascii_case(".module lib"))
            .expect("lib module in combined output");
        let app_idx = combined
            .iter()
            .position(|line| line.trim().eq_ignore_ascii_case(".module app"))
            .expect("app module in combined output");

        assert!(lib_idx < app_idx, "lib module should come before app");
    }

    #[test]
    fn module_loader_reports_missing_module() {
        let dir = create_temp_dir("module-missing");
        let root_path = dir.join("main.asm");

        write_file(
            &root_path,
            ".module app\n    .use missing.mod\n.endmodule\n",
        );

        let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
        let err = load_module_graph(&root_path, root_lines, &[], 32)
            .expect_err("expected missing module error");
        assert!(
            err.to_string().contains("Missing module"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn module_loader_missing_module_includes_import_stack() {
        let dir = create_temp_dir("module-missing-stack");
        let root_path = dir.join("main.asm");
        let lib_path = dir.join("lib.asm");

        write_file(&root_path, ".module app\n    .use lib\n.endmodule\n");
        write_file(&lib_path, ".module lib\n    .use missing\n.endmodule\n");

        let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
        let err = load_module_graph(&root_path, root_lines, &[], 32)
            .expect_err("expected missing module error");
        let message = err.to_string();
        assert!(
            message.contains("import stack"),
            "missing import stack: {message}"
        );
        assert!(message.contains("lib"), "missing lib in stack: {message}");
    }

    #[test]
    fn module_loader_reports_ambiguous_module_id() {
        let dir = create_temp_dir("module-ambiguous");
        let root_path = dir.join("main.asm");
        let a_path = dir.join("a.asm");
        let b_path = dir.join("b.asm");

        write_file(&root_path, ".module app\n    .use lib\n.endmodule\n");
        write_file(&a_path, ".module lib\n.endmodule\n");
        write_file(&b_path, ".module lib\n.endmodule\n");

        let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
        let err = load_module_graph(&root_path, root_lines, &[], 32)
            .expect_err("expected ambiguous module id");
        assert!(
            err.to_string().contains("Ambiguous module"),
            "unexpected error: {err}"
        );
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

    fn expected_example_error(base: &str) -> Option<&'static str> {
        match base {
            "errors" => Some("Assembly failed: Illegal character in decimal constant: 5X5"),
            "statement_signature_error" => Some("Preprocess failed: Missing closing }]"),
            "statement_unquoted_comma_error" => {
                Some("Preprocess failed: Commas must be quoted in statement signatures")
            }
            "module_use_private_error" => Some("Assembly failed: Symbol is private: SECRET"),
            _ => None,
        }
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
        let out_dir =
            repo_root
                .join("target")
                .join(format!("example-outputs-{}-{}", process::id(), nanos));
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

            let expected_error = expected_example_error(base);
            if let Some(expected) = expected_error {
                let err = assemble_example_error(&asm_path)
                    .unwrap_or_else(|| panic!("Expected {base} to fail but it succeeded"));
                assert_eq!(err, expected, "Unexpected error for {base}");
                continue;
            }

            match assemble_example(&asm_path, &out_dir) {
                Ok(()) => {}
                Err(err) => panic!("Failed to assemble {base}: {err}"),
            }

            let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
                .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
            let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
                .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
            let ref_hex_path = reference_dir.join(format!("{base}.hex"));
            let ref_lst_path = reference_dir.join(format!("{base}.lst"));
            if update_reference {
                fs::write(&ref_hex_path, &out_hex).unwrap_or_else(|err| {
                    panic!(
                        "Failed to write reference hex {}: {err}",
                        ref_hex_path.display()
                    )
                });
                fs::write(&ref_lst_path, &out_lst).unwrap_or_else(|err| {
                    panic!(
                        "Failed to write reference list {}: {err}",
                        ref_lst_path.display()
                    )
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
    fn project_root_example_matches_reference_outputs() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example_dir = repo_root.join("examples").join("project_root");
        let asm_path = example_dir.join("main.asm");
        let reference_dir = repo_root.join("examples").join("reference");
        let update_reference = std::env::var("opForge_UPDATE_REFERENCE").is_ok();

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let out_dir =
            repo_root
                .join("target")
                .join(format!("example-outputs-{}-{}", process::id(), nanos));
        fs::create_dir_all(&out_dir).expect("Create example output directory");
        if update_reference {
            fs::create_dir_all(&reference_dir).expect("Create reference directory");
        }

        let base = "project_root-main";
        assemble_example_with_base(&asm_path, &out_dir, base)
            .unwrap_or_else(|err| panic!("Failed to assemble project_root example: {err}"));

        let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
            .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
        let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
            .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
        let ref_hex_path = reference_dir.join(format!("{base}.hex"));
        let ref_lst_path = reference_dir.join(format!("{base}.lst"));
        if update_reference {
            fs::write(&ref_hex_path, &out_hex).unwrap_or_else(|err| {
                panic!(
                    "Failed to write reference hex {}: {err}",
                    ref_hex_path.display()
                )
            });
            fs::write(&ref_lst_path, &out_lst).unwrap_or_else(|err| {
                panic!(
                    "Failed to write reference list {}: {err}",
                    ref_lst_path.display()
                )
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
    fn module_scopes_qualify_symbols() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module alpha", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, ".endmodule", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.symbols().lookup("alpha.VAL"), Some(1));
    }

    #[test]
    fn module_duplicate_ids_error() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module alpha", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".endmodule", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".module alpha", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn missing_endmodule_emits_diagnostic() {
        let assembler = run_pass1(&[".module alpha", "VAL .const 1"]);
        assert!(assembler
            .diagnostics
            .iter()
            .any(|diag| diag.error.message().contains(".endmodule")));
    }

    #[test]
    fn section_injects_bytes_at_dsection() {
        let lines = vec![
            ".module main".to_string(),
            ".section data".to_string(),
            ".byte 1, 2".to_string(),
            ".endsection".to_string(),
            ".org 1000h".to_string(),
            ".dsection data".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        assembler.clear_diagnostics();
        let pass1 = assembler.pass1(&lines);
        assert_eq!(pass1.errors, 0);

        let mut output = Vec::new();
        let mut listing = ListingWriter::new(&mut output, false);
        listing
            .header("opForge 8085 Assembler v1.0")
            .expect("listing header");
        let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
        listing
            .footer(&pass2, assembler.symbols(), assembler.image().num_entries())
            .expect("listing footer");

        let mut hex = Vec::new();
        assembler
            .image()
            .write_hex_file(&mut hex, None)
            .expect("hex output");
        let hex_text = String::from_utf8_lossy(&hex);
        assert!(
            hex_text.contains(":021000000102EB"),
            "unexpected hex output: {hex_text}"
        );
    }

    #[test]
    fn missing_endsection_emits_diagnostic() {
        let assembler = run_pass1(&[".module alpha", ".section data", ".byte 1"]);
        assert!(assembler
            .diagnostics
            .iter()
            .any(|diag| diag.error.message().contains(".endsection")));
    }

    #[test]
    fn align_inserts_padding_bytes() {
        let lines = vec![
            ".module main".to_string(),
            ".org 1000h".to_string(),
            ".byte 1".to_string(),
            ".align 4".to_string(),
            ".byte 2".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        assembler.clear_diagnostics();
        let pass1 = assembler.pass1(&lines);
        assert_eq!(pass1.errors, 0);

        let mut output = Vec::new();
        let mut listing = ListingWriter::new(&mut output, false);
        listing
            .header("opForge 8085 Assembler v1.0")
            .expect("listing header");
        let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
        listing
            .footer(&pass2, assembler.symbols(), assembler.image().num_entries())
            .expect("listing footer");

        let mut hex = Vec::new();
        assembler
            .image()
            .write_hex_file(&mut hex, None)
            .expect("hex output");
        let hex_text = String::from_utf8_lossy(&hex);
        assert!(
            hex_text.contains(":0110000001EE"),
            "unexpected hex output: {hex_text}"
        );
        assert!(
            hex_text.contains(":0110040002E9"),
            "unexpected hex output: {hex_text}"
        );
    }

    #[test]
    fn module_rejects_top_level_content_before_explicit_modules() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "VAL .const 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, ".module alpha", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn use_selective_import_resolves_unqualified_name() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = vec![
            ".module alpha".to_string(),
            ".pub".to_string(),
            "VAL .const 1".to_string(),
            ".endmodule".to_string(),
            ".module beta".to_string(),
            ".use alpha (VAL)".to_string(),
            "    .word VAL".to_string(),
            ".endmodule".to_string(),
        ];

        let mut asm_pass1 = make_asm_line(&mut symbols, &registry);
        for line in &lines {
            let _ = process_line(&mut asm_pass1, line, 0, 1);
        }

        let mut asm_pass2 = make_asm_line(&mut symbols, &registry);
        let mut status = LineStatus::Ok;
        for line in &lines {
            status = process_line(&mut asm_pass2, line, 0, 2);
            if line.contains(".word") {
                break;
            }
        }
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm_pass2.bytes(), &[1, 0]);
    }

    #[test]
    fn use_alias_import_resolves_qualified_name() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = vec![
            ".module alpha".to_string(),
            ".pub".to_string(),
            "VAL .const 2".to_string(),
            ".endmodule".to_string(),
            ".module beta".to_string(),
            ".use alpha as A".to_string(),
            "    .word A.VAL".to_string(),
            ".endmodule".to_string(),
        ];

        let mut asm_pass1 = make_asm_line(&mut symbols, &registry);
        for line in &lines {
            let _ = process_line(&mut asm_pass1, line, 0, 1);
        }

        let mut asm_pass2 = make_asm_line(&mut symbols, &registry);
        let mut status = LineStatus::Ok;
        for line in &lines {
            status = process_line(&mut asm_pass2, line, 0, 2);
            if line.contains(".word") {
                break;
            }
        }
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm_pass2.bytes(), &[2, 0]);
    }

    #[test]
    fn use_missing_module_emits_diagnostic() {
        let assembler = run_pass1(&[".module alpha", ".use missing.mod", ".endmodule"]);
        assert!(assembler
            .diagnostics
            .iter()
            .any(|diag| diag.error.kind() == AsmErrorKind::Directive));
    }

    #[test]
    fn use_private_selective_symbol_emits_diagnostic() {
        let assembler = run_pass1(&[
            ".module alpha",
            "VAL .const 1",
            ".endmodule",
            ".module beta",
            ".use alpha (VAL)",
            ".endmodule",
        ]);
        assert!(assembler
            .diagnostics
            .iter()
            .any(|diag| diag.error.kind() == AsmErrorKind::Symbol));
    }

    #[test]
    fn use_alias_collision_errors() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = [
            ".module alpha",
            ".endmodule",
            ".module beta",
            ".use alpha as A",
            ".use alpha as A",
        ];
        let mut asm = make_asm_line(&mut symbols, &registry);
        for (idx, line) in lines.iter().enumerate() {
            let status = process_line(&mut asm, line, 0, 1);
            if idx == 4 {
                assert_eq!(status, LineStatus::Error);
                assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
            }
        }
    }

    #[test]
    fn use_selective_collision_errors() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = [
            ".module alpha",
            ".pub",
            "VAL .const 1",
            ".endmodule",
            ".module beta",
            ".use alpha (VAL)",
            ".use alpha (VAL)",
        ];
        let mut asm = make_asm_line(&mut symbols, &registry);
        for (idx, line) in lines.iter().enumerate() {
            let status = process_line(&mut asm, line, 0, 1);
            if idx == 6 {
                assert_eq!(status, LineStatus::Error);
                assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
            }
        }
    }

    #[test]
    fn use_import_cycle_emits_diagnostic() {
        let assembler = run_pass1(&[
            ".module moda",
            ".use modb",
            ".endmodule",
            ".module modb",
            ".use moda",
            ".endmodule",
        ]);
        assert!(assembler
            .diagnostics
            .iter()
            .any(|diag| diag.error.message().contains("Import cycle detected")));
    }

    #[test]
    fn root_metadata_conditional_applies_last_active() {
        let lines = vec![
            ".module main".to_string(),
            ".if 0".to_string(),
            ".meta.output.name \"nope\"".to_string(),
            ".else".to_string(),
            ".meta.output.name \"ok\"".to_string(),
            ".endif".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        let _ = assembler.pass1(&lines);
        let output = assembler.root_metadata.output_config_for_cpu("i8085");
        assert_eq!(output.name.as_deref(), Some("ok"));
    }

    #[test]
    fn root_metadata_target_specific_output_is_stored() {
        let lines = vec![
            ".module main".to_string(),
            ".meta.output.z80.name \"demo-z80\"".to_string(),
            ".meta.output.name \"demo\"".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        let _ = assembler.pass1(&lines);
        let z80_output = assembler.root_metadata.output_config_for_cpu("z80");
        let default_output = assembler.root_metadata.output_config_for_cpu("i8085");
        assert_eq!(z80_output.name.as_deref(), Some("demo-z80"));
        assert_eq!(default_output.name.as_deref(), Some("demo"));
    }

    #[test]
    fn root_metadata_block_sets_values() {
        let lines = vec![
            ".module main".to_string(),
            ".meta".to_string(),
            ".name \"Meta Demo\"".to_string(),
            ".version \"1.0.0\"".to_string(),
            ".output".to_string(),
            ".name \"meta-demo\"".to_string(),
            ".z80".to_string(),
            ".name \"meta-demo-z80\"".to_string(),
            ".endz80".to_string(),
            ".endoutput".to_string(),
            ".endmeta".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        let _ = assembler.pass1(&lines);
        assert_eq!(assembler.root_metadata.name.as_deref(), Some("Meta Demo"));
        assert_eq!(assembler.root_metadata.version.as_deref(), Some("1.0.0"));
        let default_output = assembler.root_metadata.output_config_for_cpu("i8085");
        let z80_output = assembler.root_metadata.output_config_for_cpu("z80");
        assert_eq!(default_output.name.as_deref(), Some("meta-demo"));
        assert_eq!(z80_output.name.as_deref(), Some("meta-demo-z80"));
    }

    #[test]
    fn root_metadata_block_name_does_not_set_output() {
        let lines = vec![
            ".module main".to_string(),
            ".meta".to_string(),
            ".name \"Meta Name\"".to_string(),
            ".endmeta".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        let _ = assembler.pass1(&lines);
        assert_eq!(assembler.root_metadata.name.as_deref(), Some("Meta Name"));
        let output = assembler.root_metadata.output_config_for_cpu("i8085");
        assert_eq!(output.name.as_deref(), None);
    }

    #[test]
    fn root_metadata_output_selection_directives_are_stored() {
        let lines = vec![
            ".module main".to_string(),
            ".meta.output.list".to_string(),
            ".meta.output.hex \"meta-hex\"".to_string(),
            ".meta.output.bin \"0000:0003\"".to_string(),
            ".meta.output.fill \"aa\"".to_string(),
            ".endmodule".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.root_metadata.root_module_id = Some("main".to_string());
        let _ = assembler.pass1(&lines);
        let output = assembler.root_metadata.output_config_for_cpu("i8085");
        assert_eq!(output.list_name.as_deref(), Some(""));
        assert_eq!(output.hex_name.as_deref(), Some("meta-hex"));
        assert_eq!(output.bin_specs.len(), 1);
        let spec = &output.bin_specs[0];
        assert_eq!(spec.range.start, 0x0000);
        assert_eq!(spec.range.end, 0x0003);
        assert_eq!(output.fill_byte, Some(0xaa));
    }

    #[test]
    fn root_metadata_name_sets_name_only() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module main", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".name \"Project Name\"", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn root_metadata_block_rejects_non_root_module() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut metadata = RootMetadata::default();
        metadata.root_module_id = Some("main".to_string());
        let mut asm =
            AsmLine::with_cpu_and_metadata(&mut symbols, i8085_cpu_id, &registry, metadata);
        asm.clear_conditionals();
        asm.clear_scopes();
        let status = process_line(&mut asm, ".module lib", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".meta", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn endmeta_requires_meta() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module main", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".endmeta", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn endmodule_rejects_open_meta_block() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module main", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".meta", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".endmodule", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn meta_block_rejects_non_metadata_directive() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, ".module main", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".meta", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".byte 01h", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn root_metadata_rejects_non_root_module() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut metadata = RootMetadata::default();
        metadata.root_module_id = Some("main".to_string());
        let mut asm =
            AsmLine::with_cpu_and_metadata(&mut symbols, i8085_cpu_id, &registry, metadata);
        asm.clear_conditionals();
        asm.clear_scopes();
        let status = process_line(&mut asm, ".module lib", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".meta.output.name \"x\"", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn private_symbol_is_not_visible_across_modules() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = vec![
            ".module alpha".to_string(),
            "VAL .const 1".to_string(),
            ".endmodule".to_string(),
            ".module beta".to_string(),
            "    .word alpha.VAL".to_string(),
            ".endmodule".to_string(),
        ];

        let mut asm_pass1 = make_asm_line(&mut symbols, &registry);
        for line in &lines {
            let _ = process_line(&mut asm_pass1, line, 0, 1);
        }

        let mut asm_pass2 = make_asm_line(&mut symbols, &registry);
        let mut status = LineStatus::Ok;
        for line in &lines {
            status = process_line(&mut asm_pass2, line, 0, 2);
            if line.contains(".word") {
                break;
            }
        }
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm_pass2.error().unwrap().kind(), AsmErrorKind::Symbol);
    }

    #[test]
    fn public_symbol_is_visible_across_modules() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let lines = vec![
            ".module alpha".to_string(),
            ".pub".to_string(),
            "VAL .const 1".to_string(),
            ".endmodule".to_string(),
            ".module beta".to_string(),
            "    .word alpha.VAL".to_string(),
            ".endmodule".to_string(),
        ];

        let mut asm_pass1 = make_asm_line(&mut symbols, &registry);
        for line in &lines {
            let _ = process_line(&mut asm_pass1, line, 0, 1);
        }

        let mut asm_pass2 = make_asm_line(&mut symbols, &registry);
        let mut status = LineStatus::Ok;
        for line in &lines {
            status = process_line(&mut asm_pass2, line, 0, 2);
            if line.contains(".word") {
                break;
            }
        }
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm_pass2.bytes(), &[1, 0]);
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
        let status = process_line(&mut asm, "    .word $1f, %1010, 1_0_0_0, 17o, 17q", 0, 2);
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

        let status = process_line(&mut asm, "    .byte 2&&3, 0||5, 2^^3, !0, !1", 0, 2);
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
