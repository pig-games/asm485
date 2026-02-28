// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Multi-CPU Assembler - main entry point.
//!
//! This module ties together the CPU-agnostic core with CPU-specific
//! instruction encoding (8085, Z80).

mod asmline_conditionals;
mod asmline_directives;
mod asmline_directives_data;
mod asmline_directives_layout;
mod asmline_directives_metadata;
mod asmline_directives_scope;
mod asmline_directives_text;
mod asmline_eval;
mod asmline_instruction;
mod bootstrap;
pub mod cli;
mod engine;
mod output;
mod passes;
#[cfg(test)]
mod tests;

use bootstrap::*;
use engine::Assembler;
#[cfg(test)]
use output::{build_export_sections_payloads, build_linker_output_payload, build_mapfile_text};
use output::{
    emit_dependency_file, emit_export_sections, emit_labels_file, emit_linker_outputs,
    emit_mapfiles,
};

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use serde_json::json;

use crate::core::assembler::conditional::{
    ConditionalBlockKind, ConditionalContext, ConditionalStack, ConditionalSubType,
};
use crate::core::assembler::error::{
    AsmError, AsmErrorKind, AsmRunError, AsmRunReport, Diagnostic, Fixit, LineStatus, PassCounts,
    Severity,
};
use crate::core::assembler::expression::{
    apply_assignment_op, eval_binary_op, eval_unary_op, expr_span, parse_number_text, AstEvalError,
};
use crate::core::assembler::listing::{ListingLine, ListingWriter};
use crate::core::assembler::scope::ScopeStack;
use crate::core::cpu::CpuType;
use crate::core::expr_vm::compile_core_expr_to_portable_program;
use crate::core::family::AssemblerContext;
use crate::core::imagestore::ImageStore;
use crate::core::macro_processor::MacroProcessor;
use crate::core::parser as asm_parser;
use crate::core::parser::{AssignOp, Expr, Label, LineAst, ParseError};
use crate::core::preprocess::Preprocessor;
use crate::core::registry::{
    FamilyOperandSet, ModuleRegistry, OperandSet, RegistryError, ResolvedPipeline,
};
use crate::core::source_map::SourceMap;
use crate::core::symbol_table::{ImportResult, ModuleImport, SymbolTable, SymbolVisibility};
use crate::core::text_encoding::TextEncodingRegistry;
use crate::core::tokenizer::{register_checker_none, ConditionalKind, RegisterChecker, Span};
#[cfg(test)]
use std::cell::Cell;
use std::sync::Arc;

use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::intel8080::module::Intel8080FamilyOperands;
use crate::families::intel8080::FamilyOperand as IntelFamilyOperand;
use crate::families::intel8080::{
    dialect::{canonical_suggestion_for_zilog_mnemonic, map_zilog_to_canonical},
    module::FAMILY_ID as INTEL8080_FAMILY_ID,
};
use crate::families::m6800::module::Motorola6800FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::hd6309::module::HD6309CpuModule;
use crate::i8085::module::I8085CpuModule;
use crate::m45gs02::module::M45GS02CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::m6809::module::M6809CpuModule;
use crate::vm::builder::build_hierarchy_package_from_registry;
use crate::vm::runtime::HierarchyExecutionModel;
use crate::vm::token_bridge::parse_line_with_model;
use crate::z80::module::Z80CpuModule;

use cli::{
    input_base_from_path, resolve_bin_path, resolve_output_path, validate_cli, BinOutputSpec,
    BinRange, Cli, OutputFormat,
};

// Re-export public types
pub use crate::core::assembler::error::{AsmRunError as RunError, AsmRunReport as RunReport};
pub use cli::VERSION;

const DEFAULT_MODULE_EXTENSIONS: &[&str] = &["asm", "inc"];
const OPFORGE_VM_EXPR_EVAL_OPT_IN_FAMILIES_ENV: &str = "OPFORGE_VM_EXPR_EVAL_OPT_IN_FAMILIES";
const OPFORGE_VM_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV: &str =
    "OPFORGE_VM_EXPR_EVAL_FORCE_HOST_FAMILIES";
const LEGACY_OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES_ENV: &str = "OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES";
const LEGACY_OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV: &str =
    "OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES";
#[cfg(feature = "vm-runtime-opcpu-artifact")]
const VM_RUNTIME_PACKAGE_ARTIFACT_RELATIVE_PATH: &str = "target/vm/opforge-vm-runtime.opcpu";
#[cfg(test)]
thread_local! {
    static HOST_EXPR_EVAL_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_host_expr_eval_failpoint_for_tests(enabled: bool) {
    HOST_EXPR_EVAL_FAILPOINT.with(|flag| flag.set(enabled));
}

fn default_cpu() -> CpuType {
    crate::i8085::module::CPU_ID
}

pub fn capabilities_report() -> String {
    let assembler = Assembler::new();
    let registry = &assembler.registry;
    let mut lines = vec![
        "opforge-capabilities-v1".to_string(),
        format!("version={VERSION}"),
        "feature=include-path".to_string(),
        "feature=module-path".to_string(),
        "feature=input-extension-policy".to_string(),
        "feature=diagnostics-routing".to_string(),
        "feature=warning-policy".to_string(),
        "feature=cpu-override".to_string(),
        "feature=dependency-output".to_string(),
    ];

    let mut family_ids = registry.family_ids();
    family_ids.sort_by_key(|family| family.as_str());
    for family in family_ids {
        lines.push(format!("family={}", family.as_str()));
    }

    lines.extend(cpusupport_report().lines().map(|line| line.to_string()));
    format!("{}\n", lines.join("\n"))
}

pub fn cpusupport_report() -> String {
    let assembler = Assembler::new();
    let registry = &assembler.registry;
    let mut lines = vec!["opforge-cpusupport-v1".to_string()];
    let mut cpu_ids = registry.cpu_ids();
    cpu_ids.sort_by_key(|cpu| cpu.as_str());

    for cpu in cpu_ids {
        let family = registry
            .cpu_family_id(cpu)
            .map(|id| id.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let dialect = registry.cpu_default_dialect(cpu).unwrap_or("none");
        lines.push(format!(
            "cpu={};family={};default_dialect={}",
            cpu.as_str(),
            family,
            dialect
        ));
    }

    lines.join("\n")
}

pub fn cpusupport_report_json() -> String {
    cpusupport_report_json_value().to_string()
}

fn cpusupport_report_json_value() -> serde_json::Value {
    let assembler = Assembler::new();
    let registry = &assembler.registry;
    let mut cpu_ids = registry.cpu_ids();
    cpu_ids.sort_by_key(|cpu| cpu.as_str());

    let cpus: Vec<serde_json::Value> = cpu_ids
        .into_iter()
        .map(|cpu| {
            let family = registry
                .cpu_family_id(cpu)
                .map(|id| id.as_str().to_string());
            let default_dialect = registry.cpu_default_dialect(cpu).map(str::to_string);
            json!({
                "cpu": cpu.as_str(),
                "family": family,
                "default_dialect": default_dialect,
            })
        })
        .collect();

    json!({
        "schema": "opforge-cpusupport-v1",
        "cpus": cpus,
    })
}

pub fn capabilities_report_json() -> String {
    let assembler = Assembler::new();
    let registry = &assembler.registry;
    let mut family_ids = registry.family_ids();
    family_ids.sort_by_key(|family| family.as_str());
    let families: Vec<String> = family_ids
        .into_iter()
        .map(|family| family.as_str().to_string())
        .collect();
    let features = vec![
        "include-path",
        "module-path",
        "input-extension-policy",
        "diagnostics-routing",
        "warning-policy",
        "cpu-override",
        "dependency-output",
    ];

    json!({
        "schema": "opforge-capabilities-v1",
        "version": VERSION,
        "features": features,
        "families": families,
        "cpusupport": cpusupport_report_json_value(),
    })
    .to_string()
}

/// Run the assembler with command-line arguments.
pub fn run() -> Result<Vec<AsmRunReport>, AsmRunError> {
    passes::run()
}

pub fn run_with_cli(cli: &Cli) -> Result<Vec<AsmRunReport>, AsmRunError> {
    passes::run_with_cli(cli)
}

/// Resolve source files targeted by formatter mode.
///
/// File inputs map to their resolved root source file.
/// Directory inputs expand to the root module plus all linked module/include
/// source files discovered through the module graph loader.
pub fn resolve_formatter_input_paths(config: &cli::CliConfig) -> Result<Vec<PathBuf>, AsmRunError> {
    passes::resolve_formatter_input_paths(config)
}

fn format_addr(addr: u32) -> String {
    if addr <= 0xFFFF {
        format!("{addr:04X}")
    } else if addr <= 0xFF_FFFF {
        format!("{addr:06X}")
    } else {
        format!("{addr:08X}")
    }
}

fn section_kind_name(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::Code => "code",
        SectionKind::Data => "data",
        SectionKind::Bss => "bss",
    }
}

fn remap_diagnostics_with_source_map(diagnostics: &mut [Diagnostic], source_map: &SourceMap) {
    for diagnostic in diagnostics {
        remap_primary_diagnostic_span(diagnostic, source_map);
        for span in &mut diagnostic.related_spans {
            remap_span_line_file(&mut span.file, &mut span.line, source_map);
        }
        for fixit in &mut diagnostic.fixits {
            remap_span_line_file(&mut fixit.file, &mut fixit.line, source_map);
        }
    }
}

fn remap_primary_diagnostic_span(diagnostic: &mut Diagnostic, source_map: &SourceMap) {
    remap_span_line_file(&mut diagnostic.file, &mut diagnostic.line, source_map);
}

fn remap_span_line_file(file: &mut Option<String>, line: &mut u32, source_map: &SourceMap) {
    if file.is_some() || *line == 0 {
        return;
    }
    if let Some(origin) = source_map.origin_for_line(*line) {
        if let Some(origin_file) = &origin.file {
            *file = Some(origin_file.clone());
        }
        *line = origin.line;
    }
}

#[derive(Debug, Clone)]
struct EncodingScopeState {
    definition_name: String,
    previous_active_encoding: String,
}

#[derive(Debug)]
struct AsmDiagnosticsState {
    last_error: Option<AsmError>,
    last_error_column: Option<usize>,
    last_error_help: Option<String>,
    last_error_fixits: Vec<Fixit>,
    last_parser_error: Option<ParseError>,
}

impl AsmDiagnosticsState {
    fn new() -> Self {
        Self {
            last_error: None,
            last_error_column: None,
            last_error_help: None,
            last_error_fixits: Vec::new(),
            last_parser_error: None,
        }
    }
}

#[derive(Debug)]
struct AsmLayoutState {
    sections: HashMap<String, SectionState>,
    regions: HashMap<String, RegionState>,
    placement_directives: Vec<PlacementDirective>,
    section_symbol_sections: HashMap<String, String>,
    section_stack: Vec<Option<String>>,
    current_section: Option<String>,
}

impl AsmLayoutState {
    fn new() -> Self {
        Self {
            sections: HashMap::new(),
            regions: HashMap::new(),
            placement_directives: Vec::new(),
            section_symbol_sections: HashMap::new(),
            section_stack: Vec::new(),
            current_section: None,
        }
    }
}

struct AsmSymbolScopeState {
    scope_stack: ScopeStack,
    visibility_stack: Vec<SymbolVisibility>,
    module_active: Option<String>,
    module_scope_depth: usize,
    saw_explicit_module: bool,
    top_level_content_seen: bool,
}

impl AsmSymbolScopeState {
    fn new() -> Self {
        Self {
            scope_stack: ScopeStack::new(),
            visibility_stack: vec![SymbolVisibility::Private],
            module_active: None,
            module_scope_depth: 0,
            saw_explicit_module: false,
            top_level_content_seen: false,
        }
    }
}

struct AsmOutputState {
    root_metadata: RootMetadata,
    in_meta_block: bool,
    in_output_block: bool,
    output_cpu_block: Option<String>,
}

impl AsmOutputState {
    fn new(root_metadata: RootMetadata) -> Self {
        Self {
            root_metadata,
            in_meta_block: false,
            in_output_block: false,
            output_cpu_block: None,
        }
    }
}

struct AsmCpuModeState {
    program_address_max: u32,
    word_size_bytes: u32,
    little_endian: bool,
    state_flags: HashMap<String, u32>,
}

impl AsmCpuModeState {
    fn new(registry: &ModuleRegistry, cpu: CpuType) -> Self {
        Self {
            program_address_max: AsmLine::build_cpu_program_address_max(registry, cpu),
            word_size_bytes: AsmLine::build_cpu_word_size(registry, cpu),
            little_endian: AsmLine::build_cpu_endianness(registry, cpu),
            state_flags: AsmLine::build_cpu_runtime_state(registry, cpu),
        }
    }
}

/// Per-line assembler state.
struct AsmLine<'a> {
    symbols: &'a mut SymbolTable,
    registry: &'a ModuleRegistry,
    cond_stack: ConditionalStack,
    symbol_scope: AsmSymbolScopeState,
    output_state: AsmOutputState,
    layout: AsmLayoutState,
    diagnostics: AsmDiagnosticsState,
    current_line_num: u32,
    current_source_line: Option<String>,
    line_end_span: Option<Span>,
    line_end_token: Option<String>,
    bytes: Vec<u8>,
    start_addr: u32,
    aux_value: u32,
    pass: u8,
    label: Option<String>,
    mnemonic: Option<String>,
    cpu: CpuType,
    register_checker: RegisterChecker,
    cpu_mode: AsmCpuModeState,
    opthread_expr_eval_opt_in_families: Vec<String>,
    opthread_expr_eval_force_host_families: Vec<String>,
    opthread_execution_model: Option<HierarchyExecutionModel>,
    text_encoding_registry: TextEncodingRegistry,
    active_text_encoding: String,
    encoding_scope_stack: Vec<EncodingScopeState>,
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
        let text_encoding_registry = TextEncodingRegistry::new();
        let active_text_encoding = text_encoding_registry.default_encoding_name().to_string();
        Self {
            symbols,
            registry,
            cond_stack: ConditionalStack::new(),
            symbol_scope: AsmSymbolScopeState::new(),
            output_state: AsmOutputState::new(root_metadata),
            layout: AsmLayoutState::new(),
            diagnostics: AsmDiagnosticsState::new(),
            current_line_num: 1,
            current_source_line: None,
            line_end_span: None,
            line_end_token: None,
            bytes: Vec::with_capacity(256),
            start_addr: 0,
            aux_value: 0,
            pass: 1,
            label: None,
            mnemonic: None,
            cpu,
            register_checker: Self::build_register_checker(registry, cpu),
            cpu_mode: AsmCpuModeState::new(registry, cpu),
            opthread_expr_eval_opt_in_families: Self::expr_eval_opt_in_families_from_env(),
            opthread_expr_eval_force_host_families: Self::expr_eval_force_host_families_from_env(),
            opthread_execution_model: Self::build_opthread_execution_model(registry, cpu),
            text_encoding_registry,
            active_text_encoding,
            encoding_scope_stack: Vec::new(),
            statement_depth: 0,
        }
    }

    /// Build a `RegisterChecker` for the given CPU, or a no-op checker on error.
    fn build_register_checker(registry: &ModuleRegistry, cpu: CpuType) -> RegisterChecker {
        match registry.resolve_pipeline(cpu, None) {
            Ok(pipeline) => {
                let family = pipeline.family;
                Arc::new(move |ident: &str| family.is_register(ident) || family.is_condition(ident))
            }
            Err(_) => register_checker_none(),
        }
    }

    fn build_cpu_runtime_state(registry: &ModuleRegistry, cpu: CpuType) -> HashMap<String, u32> {
        match registry.resolve_pipeline(cpu, None) {
            Ok(pipeline) => pipeline.cpu.runtime_state_defaults(),
            Err(_) => HashMap::new(),
        }
    }

    fn build_cpu_program_address_max(registry: &ModuleRegistry, cpu: CpuType) -> u32 {
        match registry.resolve_pipeline(cpu, None) {
            Ok(pipeline) => pipeline.cpu.max_program_address(),
            Err(_) => 0xFFFF,
        }
    }

    fn build_cpu_word_size(registry: &ModuleRegistry, cpu: CpuType) -> u32 {
        match registry.resolve_pipeline(cpu, None) {
            Ok(pipeline) => pipeline.cpu.native_word_size_bytes().max(1),
            Err(_) => 2,
        }
    }

    fn build_cpu_endianness(registry: &ModuleRegistry, cpu: CpuType) -> bool {
        match registry.resolve_pipeline(cpu, None) {
            Ok(pipeline) => pipeline.cpu.is_little_endian(),
            Err(_) => true,
        }
    }

    fn parse_family_list_from_env(var_name: &str) -> Vec<String> {
        let Ok(raw) = env::var(var_name) else {
            return Vec::new();
        };

        let mut families = Vec::new();
        for candidate in raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            if !families
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(candidate))
            {
                families.push(candidate.to_string());
            }
        }
        families
    }

    fn expr_eval_opt_in_families_from_env() -> Vec<String> {
        let mut families =
            Self::parse_family_list_from_env(OPFORGE_VM_EXPR_EVAL_OPT_IN_FAMILIES_ENV);
        for candidate in
            Self::parse_family_list_from_env(LEGACY_OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES_ENV)
        {
            if !families
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(candidate.as_str()))
            {
                families.push(candidate);
            }
        }
        families
    }

    fn expr_eval_force_host_families_from_env() -> Vec<String> {
        let mut families =
            Self::parse_family_list_from_env(OPFORGE_VM_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV);
        for candidate in
            Self::parse_family_list_from_env(LEGACY_OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV)
        {
            if !families
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(candidate.as_str()))
            {
                families.push(candidate);
            }
        }
        families
    }

    fn portable_expr_runtime_enabled_for_family(&self, family_id: &str) -> bool {
        crate::vm::rollout::portable_expr_runtime_enabled_for_family(
            family_id,
            &self.opthread_expr_eval_opt_in_families,
            &self.opthread_expr_eval_force_host_families,
        )
    }

    fn portable_expr_runtime_force_host_for_family(&self, family_id: &str) -> bool {
        self.opthread_expr_eval_force_host_families
            .iter()
            .any(|force_host| force_host.eq_ignore_ascii_case(family_id))
    }

    fn build_opthread_execution_model(
        registry: &ModuleRegistry,
        cpu: CpuType,
    ) -> Option<HierarchyExecutionModel> {
        if registry.resolve_pipeline(cpu, None).is_err() {
            return None;
        }

        #[cfg(feature = "vm-runtime-opcpu-artifact")]
        {
            if let Some(path) = Self::opthread_package_artifact_path() {
                if let Some(model) = Self::load_opthread_execution_model_from_artifact(&path) {
                    return Some(model);
                }
                if let Ok(package_bytes) = build_hierarchy_package_from_registry(registry) {
                    if let Ok(model) =
                        HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
                    {
                        Self::persist_opthread_package_artifact(path.as_path(), &package_bytes);
                        return Some(model);
                    }
                }
                return None;
            }
        }

        let package_bytes = build_hierarchy_package_from_registry(registry).ok()?;
        HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice()).ok()
    }

    #[cfg(feature = "vm-runtime-opcpu-artifact")]
    fn opthread_package_artifact_path_for_dir(base_dir: &Path) -> PathBuf {
        base_dir.join(VM_RUNTIME_PACKAGE_ARTIFACT_RELATIVE_PATH)
    }

    #[cfg(feature = "vm-runtime-opcpu-artifact")]
    fn opthread_package_artifact_path() -> Option<PathBuf> {
        std::env::current_dir()
            .ok()
            .map(|base_dir| Self::opthread_package_artifact_path_for_dir(base_dir.as_path()))
    }

    #[cfg(feature = "vm-runtime-opcpu-artifact")]
    fn load_opthread_execution_model_from_artifact(path: &Path) -> Option<HierarchyExecutionModel> {
        let bytes = fs::read(path).ok()?;
        HierarchyExecutionModel::from_package_bytes(bytes.as_slice()).ok()
    }

    #[cfg(feature = "vm-runtime-opcpu-artifact")]
    fn persist_opthread_package_artifact(path: &Path, package_bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, package_bytes);
    }

    fn take_root_metadata(&mut self) -> RootMetadata {
        std::mem::take(&mut self.output_state.root_metadata)
    }

    fn take_placement_directives(&mut self) -> Vec<PlacementDirective> {
        std::mem::take(&mut self.layout.placement_directives)
    }

    fn take_sections(&mut self) -> HashMap<String, SectionState> {
        std::mem::take(&mut self.layout.sections)
    }

    fn take_regions(&mut self) -> HashMap<String, RegionState> {
        std::mem::take(&mut self.layout.regions)
    }

    fn finalize_section_symbol_addresses(&mut self) -> Vec<AsmError> {
        let section_symbols = std::mem::take(&mut self.layout.section_symbol_sections);
        let mut errors = Vec::new();
        let cpu_name = self.cpu.as_str().to_string();
        for (symbol_name, section_name) in section_symbols {
            let Some(base_addr) = self
                .layout
                .sections
                .get(&section_name)
                .and_then(|s| s.base_addr)
            else {
                continue;
            };
            if let Some(entry) = self.symbols.entry_mut(&symbol_name) {
                match entry.val.checked_add(base_addr) {
                    Some(value) => {
                        entry.val = value;
                        entry.updated = true;
                    }
                    None => {
                        let message = format!(
                            "Section symbol address overflows address arithmetic for CPU {cpu_name}"
                        );
                        errors.push(AsmError::new(
                            AsmErrorKind::Directive,
                            &message,
                            Some(&symbol_name),
                        ));
                    }
                }
            }
        }
        errors
    }

    fn error(&self) -> Option<&AsmError> {
        self.diagnostics.last_error.as_ref()
    }

    fn error_column(&self) -> Option<usize> {
        self.diagnostics.last_error_column
    }

    fn error_help(&self) -> Option<&str> {
        self.diagnostics.last_error_help.as_deref()
    }

    fn error_fixits(&self) -> &[Fixit] {
        &self.diagnostics.last_error_fixits
    }

    fn parser_error(&self) -> Option<ParseError> {
        self.diagnostics.last_parser_error.clone()
    }

    fn parser_error_ref(&self) -> Option<&ParseError> {
        self.diagnostics.last_parser_error.as_ref()
    }

    #[cfg(test)]
    fn error_message(&self) -> &str {
        self.diagnostics
            .last_error
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

    fn start_addr(&self) -> u32 {
        self.start_addr
    }

    fn aux_value(&self) -> u32 {
        self.aux_value
    }

    fn clear_conditionals(&mut self) {
        self.cond_stack.clear();
    }

    fn clear_scopes(&mut self) {
        self.symbol_scope.scope_stack.clear();
        self.symbol_scope.visibility_stack.clear();
        self.symbol_scope
            .visibility_stack
            .push(SymbolVisibility::Private);
        self.symbol_scope.module_active = None;
        self.symbol_scope.module_scope_depth = 0;
        self.output_state.in_meta_block = false;
        self.output_state.in_output_block = false;
        self.output_state.output_cpu_block = None;
        self.layout.sections.clear();
        self.layout.regions.clear();
        self.layout.placement_directives.clear();
        self.layout.section_symbol_sections.clear();
        self.layout.section_stack.clear();
        self.layout.current_section = None;
        self.symbol_scope.saw_explicit_module = false;
        self.symbol_scope.top_level_content_seen = false;
        self.reset_cpu_runtime_profile();
        self.reset_text_encoding_profile();
    }

    fn reset_cpu_runtime_profile(&mut self) {
        self.cpu_mode = AsmCpuModeState::new(self.registry, self.cpu);
    }

    fn reset_text_encoding_profile(&mut self) {
        self.active_text_encoding = self
            .text_encoding_registry
            .default_encoding_name()
            .to_string();
        self.encoding_scope_stack.clear();
    }

    fn apply_cpu_runtime_state_after_encode(
        &mut self,
        cpu_handler: &dyn crate::core::registry::CpuHandlerDyn,
        mnemonic: &str,
        operands: &dyn crate::core::registry::OperandSet,
    ) {
        cpu_handler.update_runtime_state_after_encode(
            mnemonic,
            operands,
            &mut self.cpu_mode.state_flags,
        );
    }

    fn resolve_pipeline_for_cpu<'b>(
        registry: &'b ModuleRegistry,
        cpu: CpuType,
    ) -> Result<crate::core::registry::ResolvedPipeline<'b>, String> {
        registry
            .resolve_pipeline(cpu, None)
            .map_err(registry_error_message)
    }

    fn apply_cpu_runtime_directive(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Result<bool, String> {
        let pipeline = Self::resolve_pipeline_for_cpu(self.registry, self.cpu)?;
        let mut state_flags = std::mem::take(&mut self.cpu_mode.state_flags);
        let result =
            pipeline
                .cpu
                .apply_runtime_directive(directive, operands, self, &mut state_flags);
        self.cpu_mode.state_flags = state_flags;
        result
    }

    fn opthread_form_allows_mnemonic(
        &self,
        pipeline: &crate::core::registry::ResolvedPipeline<'_>,
        mapped_mnemonic: &str,
    ) -> Result<bool, String> {
        if !crate::vm::rollout::package_runtime_default_enabled_for_family(
            pipeline.family_id.as_str(),
        ) {
            return Ok(true);
        }
        let Some(model) = self.opthread_execution_model.as_ref() else {
            return Ok(true);
        };
        model
            .supports_mnemonic(self.cpu.as_str(), None, mapped_mnemonic)
            .map_err(|err| err.to_string())
    }

    fn opthread_runtime_expr_operands_from_mapped(
        mapped_operands: &dyn crate::core::registry::FamilyOperandSet,
    ) -> Option<Vec<Expr>> {
        let intel_operands = mapped_operands
            .as_any()
            .downcast_ref::<Intel8080FamilyOperands>()?;
        let mut exprs = Vec::with_capacity(intel_operands.0.len());
        for operand in &intel_operands.0 {
            let expr = match operand {
                IntelFamilyOperand::Register(name, span)
                | IntelFamilyOperand::Condition(name, span) => {
                    Expr::Identifier(name.clone(), *span)
                }
                IntelFamilyOperand::Indirect(name, span) => {
                    Expr::Indirect(Box::new(Expr::Identifier(name.clone(), *span)), *span)
                }
                IntelFamilyOperand::Immediate(expr)
                | IntelFamilyOperand::RstVector(expr)
                | IntelFamilyOperand::InterruptMode(expr)
                | IntelFamilyOperand::BitNumber(expr)
                | IntelFamilyOperand::Port(expr) => expr.clone(),
                IntelFamilyOperand::Indexed { base, offset, span } => Expr::Indirect(
                    Box::new(Expr::Binary {
                        op: asm_parser::BinaryOp::Add,
                        left: Box::new(Expr::Identifier(base.clone(), *span)),
                        right: Box::new(offset.clone()),
                        span: *span,
                    }),
                    *span,
                ),
            };
            exprs.push(expr);
        }
        Some(exprs)
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
        self.symbol_scope.module_active.is_some()
    }

    fn in_section(&self) -> bool {
        self.layout.current_section.is_some()
    }

    fn current_section_name(&self) -> Option<&str> {
        self.layout.current_section.as_deref()
    }

    fn current_addr(&mut self, main_addr: u32) -> Result<u32, ()> {
        match self.layout.current_section.as_deref() {
            Some(name) => {
                let Some(section) = self.layout.sections.get(name) else {
                    return Ok(main_addr);
                };
                let max = self.max_program_address();
                let cpu_name = self.cpu.as_str().to_string();
                let label = format!("section {name} absolute address");
                match Self::checked_add_address(
                    section.start_pc,
                    section.pc,
                    max,
                    cpu_name.as_str(),
                    label.as_str(),
                ) {
                    Ok(addr) => Ok(addr),
                    Err(message) => {
                        self.diagnostics.last_error =
                            Some(AsmError::new(AsmErrorKind::Directive, &message, None));
                        self.diagnostics.last_error_column = None;
                        Err(())
                    }
                }
            }
            None => Ok(main_addr),
        }
    }

    fn track_section_symbol(&mut self, full_name: &str) {
        if self.pass != 1 {
            return;
        }
        if let Some(section_name) = self.layout.current_section.as_ref() {
            self.layout
                .section_symbol_sections
                .insert(full_name.to_string(), section_name.clone());
        }
    }

    fn update_addresses(&mut self, main_addr: &mut u32, status: LineStatus) -> Result<(), ()> {
        let num_bytes = match u32::try_from(self.num_bytes()) {
            Ok(num_bytes) => num_bytes,
            Err(_) => {
                let message = format!(
                    "line byte count exceeds supported range for CPU {}",
                    self.cpu.as_str()
                );
                return self.fail_address_update(message);
            }
        };
        let max = self.max_program_address();
        let cpu_name = self.cpu.as_str().to_string();
        if let Some(section_name) = self.layout.current_section.clone() {
            let update_result: Result<(), String> = (|| {
                let Some(section) = self.layout.sections.get_mut(&section_name) else {
                    return Ok(());
                };
                let current_abs = Self::checked_add_address(
                    section.start_pc,
                    section.pc,
                    max,
                    cpu_name.as_str(),
                    &format!("section {section_name} absolute address"),
                )?;
                if self.pass == 2 {
                    if status == LineStatus::DirDs && self.aux_value > 0 && !section.is_bss() {
                        section
                            .bytes
                            .extend(std::iter::repeat_n(0, self.aux_value as usize));
                    } else if status == LineStatus::DirEqu
                        && self.start_addr > current_abs
                        && !section.is_bss()
                    {
                        let pad = self.start_addr - current_abs;
                        section.bytes.extend(std::iter::repeat_n(0, pad as usize));
                    } else if !self.bytes.is_empty() && !section.is_bss() {
                        section.bytes.extend_from_slice(&self.bytes);
                    }
                }
                section.pc = if status == LineStatus::DirDs {
                    let current_abs = Self::checked_add_address(
                        section.pc,
                        self.aux_value,
                        max,
                        cpu_name.as_str(),
                        &format!("section {section_name} program counter"),
                    )?;
                    current_abs
                } else if status == LineStatus::DirEqu {
                    Self::checked_sub_address(
                        self.start_addr,
                        section.start_pc,
                        max,
                        cpu_name.as_str(),
                        &format!("section {section_name} program counter"),
                    )?
                } else {
                    Self::checked_add_address(
                        section.pc,
                        num_bytes,
                        max,
                        cpu_name.as_str(),
                        &format!("section {section_name} program counter"),
                    )?
                };
                let _ = Self::checked_add_address(
                    section.start_pc,
                    section.pc,
                    max,
                    cpu_name.as_str(),
                    &format!("section {section_name} absolute address"),
                )?;
                section.max_pc = section.max_pc.max(section.pc);
                Ok(())
            })();
            if let Err(message) = update_result {
                return self.fail_address_update(message);
            }
        } else if status == LineStatus::DirDs {
            match Self::checked_add_address(
                *main_addr,
                self.aux_value,
                max,
                cpu_name.as_str(),
                "program counter",
            ) {
                Ok(addr) => *main_addr = addr,
                Err(message) => return self.fail_address_update(message),
            }
        } else if status == LineStatus::DirEqu {
            if self.start_addr > max {
                let message = format!(
                    "program counter ${} exceeds max ${} for CPU {}",
                    format_addr(self.start_addr),
                    format_addr(max),
                    cpu_name
                );
                return self.fail_address_update(message);
            }
            *main_addr = self.start_addr;
        } else {
            match Self::checked_add_address(
                *main_addr,
                num_bytes,
                max,
                cpu_name.as_str(),
                "program counter",
            ) {
                Ok(addr) => *main_addr = addr,
                Err(message) => return self.fail_address_update(message),
            }
        }
        Ok(())
    }

    fn checked_add_address(
        start: u32,
        delta: u32,
        max: u32,
        cpu_name: &str,
        label: &str,
    ) -> Result<u32, String> {
        let value = start
            .checked_add(delta)
            .ok_or_else(|| format!("{label} overflows address arithmetic for CPU {cpu_name}"))?;
        if value > max {
            return Err(format!(
                "{label} ${} exceeds max ${} for CPU {}",
                format_addr(value),
                format_addr(max),
                cpu_name
            ));
        }
        Ok(value)
    }

    fn checked_sub_address(
        value: u32,
        subtrahend: u32,
        max: u32,
        cpu_name: &str,
        label: &str,
    ) -> Result<u32, String> {
        let result = value
            .checked_sub(subtrahend)
            .ok_or_else(|| format!("{label} underflows address arithmetic for CPU {cpu_name}"))?;
        if result > max {
            return Err(format!(
                "{label} ${} exceeds max ${} for CPU {}",
                format_addr(result),
                format_addr(max),
                cpu_name
            ));
        }
        Ok(result)
    }

    fn fail_address_update(&mut self, message: String) -> Result<(), ()> {
        self.diagnostics.last_error = Some(AsmError::new(AsmErrorKind::Directive, &message, None));
        self.diagnostics.last_error_column = self.line_end_span.map(|span| span.col_start);
        Err(())
    }

    fn is_allowed_meta_directive(&self, mnemonic: &str) -> bool {
        if self.output_state.in_output_block {
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
        self.symbol_scope
            .visibility_stack
            .last()
            .copied()
            .unwrap_or(SymbolVisibility::Private)
    }

    fn push_visibility(&mut self) {
        let current = self.current_visibility();
        self.symbol_scope.visibility_stack.push(current);
    }

    fn pop_visibility(&mut self) -> bool {
        if self.symbol_scope.visibility_stack.len() > 1 {
            self.symbol_scope.visibility_stack.pop();
            true
        } else {
            false
        }
    }

    fn set_visibility(&mut self, visibility: SymbolVisibility) {
        if let Some(current) = self.symbol_scope.visibility_stack.last_mut() {
            *current = visibility;
        } else {
            self.symbol_scope.visibility_stack.push(visibility);
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
            self.symbol_scope.scope_stack.qualify(name)
        }
    }

    fn resolve_imported_name(&self, name: &str) -> Option<String> {
        let module_id = self.symbol_scope.module_active.as_deref()?;
        let (target_module, target_name) =
            self.symbols.resolve_selective_import(module_id, name)?;
        Some(format!("{target_module}.{target_name}"))
    }

    fn resolve_import_alias(&self, name: &str) -> Option<String> {
        let module_id = self.symbol_scope.module_active.as_deref()?;
        let (prefix, rest) = name.split_once('.')?;
        let target_module = self.symbols.resolve_import_alias(module_id, prefix)?;
        Some(format!("{target_module}.{rest}"))
    }

    fn selective_import_conflict(&self, name: &str) -> bool {
        if name.contains('.') {
            return false;
        }
        let module_id = match self.symbol_scope.module_active.as_deref() {
            Some(module_id) => module_id,
            None => return false,
        };
        if self.symbol_scope.scope_stack.depth() != self.symbol_scope.module_scope_depth {
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
        let mut depth = self.symbol_scope.scope_stack.depth();
        while depth > 0 {
            let prefix = self.symbol_scope.scope_stack.prefix(depth);
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
        let mut depth = self.symbol_scope.scope_stack.depth();
        while depth > 0 {
            let prefix = self.symbol_scope.scope_stack.prefix(depth);
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
            SymbolVisibility::Private => match (&entry.module_id, &self.symbol_scope.module_active)
            {
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
    fn process_with_runtime_tokenizer(&mut self, line: &str, line_num: u32) -> LineStatus {
        let model = match self.opthread_execution_model.as_ref() {
            Some(model) => model,
            None => {
                let family_id = Self::resolve_pipeline_for_cpu(self.registry, self.cpu)
                    .map(|pipeline| pipeline.family_id.as_str().to_string())
                    .unwrap_or_else(|_| self.cpu.as_str().to_string());
                let err = ParseError {
                    message: format!(
                        "VM runtime tokenizer model unavailable for family '{}'",
                        family_id
                    ),
                    span: Span {
                        line: line_num,
                        col_start: 1,
                        col_end: 1,
                    },
                };
                self.diagnostics.last_error =
                    Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.diagnostics.last_error_column = Some(err.span.col_start);
                self.diagnostics.last_parser_error = Some(err);
                return LineStatus::Error;
            }
        };

        let (ast, end_span, end_token_text) = match parse_line_with_model(
            model,
            self.cpu.as_str(),
            None,
            line,
            line_num,
            &self.register_checker,
        ) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.line_end_span = Some(err.span);
                self.diagnostics.last_error =
                    Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.diagnostics.last_error_column = Some(err.span.col_start);
                self.diagnostics.last_parser_error = Some(err);
                self.attach_dialect_fixit_hint_from_source_line();
                return LineStatus::Error;
            }
        };

        self.line_end_span = Some(end_span);
        self.line_end_token = end_token_text;
        self.process_ast(ast)
    }

    fn process(&mut self, line: &str, line_num: u32, addr: u32, pass: u8) -> LineStatus {
        self.diagnostics.last_error = None;
        self.diagnostics.last_error_column = None;
        self.diagnostics.last_error_help = None;
        self.diagnostics.last_error_fixits.clear();
        self.diagnostics.last_parser_error = None;
        self.current_line_num = line_num;
        self.current_source_line = Some(line.to_string());
        self.line_end_span = None;
        self.line_end_token = None;
        self.start_addr = addr;
        self.pass = pass;
        self.bytes.clear();
        self.aux_value = 0;

        self.label = None;
        self.mnemonic = None;

        self.process_with_runtime_tokenizer(line, line_num)
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
            if self.symbol_scope.saw_explicit_module {
                if !matches!(ast, LineAst::Empty) && !Self::ast_is_toplevel_directive(&ast) {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Top-level content must be inside a .module block",
                        None,
                    );
                }
            } else if !matches!(ast, LineAst::Empty) && !Self::ast_is_toplevel_directive(&ast) {
                self.symbol_scope.top_level_content_seen = true;
            }
        }

        if self.output_state.in_meta_block && !self.cond_stack.skipping() {
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
                if self.symbol_scope.scope_stack.depth() != self.symbol_scope.module_scope_depth {
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
                    let module_name = self
                        .symbol_scope
                        .module_active
                        .as_deref()
                        .expect("module active");
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
            LineAst::Place {
                section,
                region,
                align,
                span,
            } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.process_place_ast(&section, &region, align.as_ref(), span)
            }
            LineAst::Pack {
                region,
                sections,
                span,
            } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.process_pack_ast(&region, &sections, span)
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
                            if let Some(status) = self.define_statement_label(label) {
                                return status;
                            }
                        }
                        return LineStatus::NothingDone;
                    }
                };

                if let Some(label) = &label {
                    if !is_symbol_assignment_directive(&mnemonic) {
                        if let Some(status) = self.define_statement_label(label) {
                            return status;
                        }
                    }
                }

                let mut status = self.process_directive_ast(&mnemonic, &operands);
                if status == LineStatus::NothingDone {
                    if mnemonic.starts_with('.') {
                        if let Some(status_with_fixit) =
                            self.failure_for_unknown_directive_with_fixit(&mnemonic)
                        {
                            return status_with_fixit;
                        }
                    }
                    status = self.process_instruction_ast(&mnemonic, &operands);
                }
                status
            }
        }
    }

    fn define_statement_label(&mut self, label: &Label) -> Option<LineStatus> {
        if self.pass == 1 && self.selective_import_conflict(&label.name) {
            return Some(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "Symbol conflicts with selective import",
                Some(&label.name),
                label.span,
            ));
        }

        let full_name = self.scoped_define_name(&label.name);
        let res = if self.pass == 1 {
            self.symbols.add(
                &full_name,
                self.start_addr,
                false,
                self.current_visibility(),
                self.symbol_scope.module_active.as_deref(),
            )
        } else if self.in_section() {
            crate::symbol_table::SymbolTableResult::Ok
        } else {
            self.symbols.update(&full_name, self.start_addr)
        };

        if res == crate::symbol_table::SymbolTableResult::Duplicate {
            return Some(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "Symbol defined more than once",
                Some(&label.name),
                label.span,
            ));
        }

        if res == crate::symbol_table::SymbolTableResult::Ok {
            self.track_section_symbol(&full_name);
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
                        self.aux_value = entry.val;
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
                        self.symbol_scope.module_active.as_deref(),
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
                self.aux_value = val;
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
        self.aux_value = new_val;
        LineStatus::DirEqu
    }

    fn current_section_kind(&self) -> Option<SectionKind> {
        self.layout
            .current_section
            .as_ref()
            .and_then(|name| self.layout.sections.get(name))
            .map(|section| section.kind)
    }

    fn max_program_address(&self) -> u32 {
        self.cpu_mode.program_address_max
    }

    fn validate_program_address(
        &self,
        value: u32,
        directive_name: &str,
        span: Span,
    ) -> Result<(), AstEvalError> {
        let max = self.max_program_address();
        if value <= max {
            return Ok(());
        }
        let message = format!(
            "{directive_name} address ${} exceeds max ${} for CPU {}",
            format_addr(value),
            format_addr(max),
            self.cpu.as_str()
        );
        Err(AstEvalError {
            error: AsmError::new(AsmErrorKind::Directive, &message, None),
            span,
        })
    }

    fn validate_program_span(
        &self,
        size_bytes: u32,
        directive_name: &str,
        span: Span,
    ) -> Result<(), AstEvalError> {
        if size_bytes == 0 {
            return Ok(());
        }
        let max = self.max_program_address();
        let start = self.start_addr;
        let end = match start.checked_add(size_bytes - 1) {
            Some(end) => end,
            None => {
                let message = format!(
                    "{directive_name} size overflows address arithmetic for CPU {}",
                    self.cpu.as_str()
                );
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Directive, &message, None),
                    span,
                });
            }
        };
        if end <= max {
            return Ok(());
        }
        let message = format!(
            "{directive_name} span ${}..${} exceeds max ${} for CPU {}",
            format_addr(start),
            format_addr(end),
            format_addr(max),
            self.cpu.as_str()
        );
        Err(AstEvalError {
            error: AsmError::new(AsmErrorKind::Directive, &message, None),
            span,
        })
    }

    fn validate_instruction_emit_span(
        &self,
        mnemonic: &str,
        operands: &[Expr],
        byte_count: usize,
    ) -> Result<(), AstEvalError> {
        let size_bytes = match u32::try_from(byte_count) {
            Ok(size_bytes) => size_bytes,
            Err(_) => {
                return Err(AstEvalError {
                    error: AsmError::new(
                        AsmErrorKind::Instruction,
                        "instruction size overflow exceeds supported range",
                        None,
                    ),
                    span: operands.first().map(expr_span).unwrap_or_default(),
                });
            }
        };
        let span = operands.first().map(expr_span).unwrap_or_default();
        let label = format!("instruction {}", mnemonic.to_ascii_uppercase());
        self.validate_program_span(size_bytes, &label, span)
    }

    fn current_cpu_little_endian(&self) -> bool {
        self.cpu_mode.little_endian
    }

    fn cpu_word_size_bytes(&self) -> u32 {
        self.cpu_mode.word_size_bytes
    }

    fn section_kind_allows_data(&self) -> bool {
        self.current_section_kind() != Some(SectionKind::Bss)
    }

    fn section_kind_requires_bss(&self) -> bool {
        self.current_section_kind() == Some(SectionKind::Bss)
    }

    fn current_section_kind_label(&self) -> &'static str {
        self.current_section_kind()
            .map(section_kind_name)
            .unwrap_or("none")
    }

    fn parse_emit_unit_bytes(&self, unit: &Expr) -> Result<u32, AstEvalError> {
        match unit {
            Expr::Identifier(name, _) | Expr::Register(name, _) => {
                if name.eq_ignore_ascii_case("byte") {
                    Ok(1)
                } else if name.eq_ignore_ascii_case("word") {
                    Ok(self.cpu_word_size_bytes())
                } else if name.eq_ignore_ascii_case("long") {
                    Ok(4)
                } else {
                    self.eval_expr_for_non_negative_directive(unit, ".emit/.fill/.res unit")
                }
            }
            _ => self.eval_expr_for_non_negative_directive(unit, ".emit/.fill/.res unit"),
        }
    }

    fn eval_expr_for_non_negative_directive(
        &self,
        expr: &Expr,
        directive_name: &str,
    ) -> Result<u32, AstEvalError> {
        if let Some((name, span)) = self.find_private_symbol_in_expr(expr) {
            return Err(AstEvalError {
                error: self.visibility_error(&name),
                span,
            });
        }

        match AssemblerContext::eval_expr(self, expr) {
            Ok(value) => {
                if value < 0 {
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            &format!("Expected non-negative value for {directive_name}"),
                            None,
                        ),
                        span: expr_span(expr),
                    });
                }

                match u32::try_from(value) {
                    Ok(value) => Ok(value),
                    Err(_) => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            &format!("Value out of supported range for {directive_name}"),
                            None,
                        ),
                        span: expr_span(expr),
                    }),
                }
            }
            Err(message) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, &message, None),
                span: expr_span(expr),
            }),
        }
    }

    fn eval_expr_for_data_directive(&self, expr: &Expr) -> Result<u32, AstEvalError> {
        if let Some((name, span)) = self.find_private_symbol_in_expr(expr) {
            return Err(AstEvalError {
                error: self.visibility_error(&name),
                span,
            });
        }

        match AssemblerContext::eval_expr(self, expr) {
            Ok(value) => Ok(value as u32),
            Err(message) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, &message, None),
                span: expr_span(expr),
            }),
        }
    }

    fn find_private_symbol_in_expr(&self, expr: &Expr) -> Option<(String, Span)> {
        match expr {
            Expr::Identifier(name, span) | Expr::Register(name, span) => {
                if let Some(entry) = self.lookup_scoped_entry(name) {
                    if !self.entry_is_visible(entry) {
                        return Some((name.clone(), *span));
                    }
                }
                None
            }
            Expr::Indirect(inner, _)
            | Expr::IndirectLong(inner, _)
            | Expr::Immediate(inner, _)
            | Expr::Unary { expr: inner, .. } => self.find_private_symbol_in_expr(inner),
            Expr::Tuple(items, _) => items
                .iter()
                .find_map(|item| self.find_private_symbol_in_expr(item)),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => self
                .find_private_symbol_in_expr(cond)
                .or_else(|| self.find_private_symbol_in_expr(then_expr))
                .or_else(|| self.find_private_symbol_in_expr(else_expr)),
            Expr::Binary { left, right, .. } => self
                .find_private_symbol_in_expr(left)
                .or_else(|| self.find_private_symbol_in_expr(right)),
            Expr::Error(_, _) | Expr::Number(_, _) | Expr::Dollar(_) | Expr::String(_, _) => None,
        }
    }

    fn write_unit_value(
        &mut self,
        unit_bytes: usize,
        value: u32,
        span: Span,
    ) -> Result<(), AstEvalError> {
        let unit_bits = unit_bytes.saturating_mul(8);
        if unit_bits < 32 {
            let max = (1u64 << unit_bits) - 1;
            if (value as u64) > max {
                let hex_width = usize::max(2, unit_bytes.saturating_mul(2));
                let max_u32 = max as u32;
                let msg = format!(
                    "Value ${value:0hex_width$X} ({value}) does not fit in {unit_bytes}-byte unit (max ${max_u32:0hex_width$X})"
                );
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Directive, &msg, None),
                    span,
                });
            }
        }

        let little_endian = self.current_cpu_little_endian();
        if little_endian {
            for shift in 0..unit_bytes {
                let byte = if shift < 4 {
                    (value >> (shift * 8)) as u8
                } else {
                    0
                };
                self.bytes.push(byte);
            }
        } else {
            for shift in (0..unit_bytes).rev() {
                let byte = if shift < 4 {
                    (value >> (shift * 8)) as u8
                } else {
                    0
                };
                self.bytes.push(byte);
            }
        }
        Ok(())
    }

    fn emit_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() < 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing unit or values for .emit",
                None,
            );
        }
        if !self.section_kind_allows_data() {
            let msg = format!(
                ".emit is not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }

        let unit_bytes = match self.parse_emit_unit_bytes(&operands[0]) {
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
        if unit_bytes == 0 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unit size must be greater than zero",
                None,
            );
        }
        let emit_count = match u32::try_from(operands.len().saturating_sub(1)) {
            Ok(count) => count,
            Err(_) => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    ".emit operand list is too large",
                    None,
                )
            }
        };
        let total = match unit_bytes.checked_mul(emit_count) {
            Some(total) => total,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    ".emit total size overflow exceeds supported range",
                    None,
                )
            }
        };
        if let Err(err) = self.validate_program_span(total, ".emit", expr_span(&operands[0])) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }

        for expr in &operands[1..] {
            let value = match self.eval_expr_for_data_directive(expr) {
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
            if let Err(err) = self.write_unit_value(unit_bytes as usize, value, expr_span(expr)) {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                );
            }
        }

        LineStatus::Ok
    }

    fn res_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() != 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .res <unit>, <count>",
                None,
            );
        }
        if !self.section_kind_requires_bss() {
            let msg = format!(
                ".res is only allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }

        let unit_bytes = match self.parse_emit_unit_bytes(&operands[0]) {
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
        if unit_bytes == 0 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unit size must be greater than zero",
                None,
            );
        }
        let count = match self.eval_expr_for_non_negative_directive(&operands[1], ".res count") {
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
        let total = match unit_bytes.checked_mul(count) {
            Some(total) => total,
            None => {
                let msg = format!(
                    ".res total size overflow (unit={unit_bytes}, count={count}) exceeds supported range"
                );
                return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
            }
        };
        if let Err(err) = self.validate_program_span(total, ".res", expr_span(&operands[1])) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        self.aux_value = total;
        LineStatus::DirDs
    }

    fn fill_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() != 3 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .fill <unit>, <count>, <value>",
                None,
            );
        }
        if !self.section_kind_allows_data() {
            let msg = format!(
                ".fill is not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }

        let unit_bytes = match self.parse_emit_unit_bytes(&operands[0]) {
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
        if unit_bytes == 0 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unit size must be greater than zero",
                None,
            );
        }
        let count = match self.eval_expr_for_non_negative_directive(&operands[1], ".fill count") {
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
        let value = match self.eval_expr_for_data_directive(&operands[2]) {
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
        let total = match unit_bytes.checked_mul(count) {
            Some(total) => total,
            None => {
                let msg = format!(
                    ".fill total size overflow (unit={unit_bytes}, count={count}) exceeds supported range"
                );
                return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
            }
        };
        if let Err(err) = self.validate_program_span(total, ".fill", expr_span(&operands[1])) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }

        for _ in 0..count {
            if let Err(err) =
                self.write_unit_value(unit_bytes as usize, value, expr_span(&operands[2]))
            {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                );
            }
        }
        LineStatus::Ok
    }

    fn store_arg_list_ast(
        &mut self,
        operands: &[Expr],
        size: usize,
        directive_name: &str,
    ) -> LineStatus {
        if !self.section_kind_allows_data() {
            let msg = format!(
                "Data emit directives are not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing expression in data list",
                None,
            );
        }

        let unit_size = size as u32;
        let mut projected_total = 0u32;
        for expr in operands {
            if let Expr::String(raw_bytes, span) = expr {
                let encoded_bytes = match self.encode_text_bytes(
                    raw_bytes,
                    *span,
                    directive_name,
                    AsmErrorKind::Directive,
                ) {
                    Ok(bytes) => bytes,
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
                if encoded_bytes.len() > 1 {
                    let string_len = match u32::try_from(encoded_bytes.len()) {
                        Ok(len) => len,
                        Err(_) => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "String literal too large to emit",
                                None,
                                *span,
                            );
                        }
                    };
                    projected_total = match projected_total.checked_add(string_len) {
                        Some(total) => total,
                        None => {
                            let msg = format!(
                                "{directive_name} total size overflow exceeds supported range"
                            );
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                &msg,
                                None,
                                *span,
                            );
                        }
                    };
                    if let Err(err) =
                        self.validate_program_span(projected_total, directive_name, *span)
                    {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        );
                    }
                    self.bytes.extend_from_slice(&encoded_bytes);
                    continue;
                }
                if encoded_bytes.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Empty string not allowed in expression list",
                        None,
                        *span,
                    );
                }
            }
            projected_total = match projected_total.checked_add(unit_size) {
                Some(total) => total,
                None => {
                    let msg =
                        format!("{directive_name} total size overflow exceeds supported range");
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &msg,
                        None,
                        expr_span(expr),
                    );
                }
            };
            if let Err(err) =
                self.validate_program_span(projected_total, directive_name, expr_span(expr))
            {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                );
            }
            let val = match self.eval_expr_for_data_directive(expr) {
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
                if val > 0xff {
                    return self.failure(
                        LineStatus::Warning,
                        AsmErrorKind::Expression,
                        "Value truncated to byte",
                        None,
                    );
                }
                self.bytes.push((val & 0xff) as u8);
            } else if size == 2 {
                self.bytes.push((val & 0xff) as u8);
                self.bytes.push((val >> 8) as u8);
            } else if size == 4 {
                self.bytes.push((val & 0xff) as u8);
                self.bytes.push(((val >> 8) & 0xff) as u8);
                self.bytes.push(((val >> 16) & 0xff) as u8);
                self.bytes.push(((val >> 24) & 0xff) as u8);
            } else {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Unsupported data size for directive",
                    None,
                );
            }
        }

        LineStatus::Ok
    }
}

fn is_identifierish(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'
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
            | ".BEND"
            | ".NAMESPACE"
            | ".ENDN"
            | ".ENDNAMESPACE"
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
