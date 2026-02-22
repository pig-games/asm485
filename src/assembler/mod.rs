// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Multi-CPU Assembler - main entry point.
//!
//! This module ties together the CPU-agnostic core with CPU-specific
//! instruction encoding (8085, Z80).

mod asmline_directives;
mod bootstrap;
pub mod cli;
mod engine;
#[cfg(test)]
mod tests;

use bootstrap::*;
use engine::Assembler;

use std::collections::{HashMap, HashSet};
use std::env;
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
use crate::core::expr_vm::compile_core_expr_to_portable_program;
use crate::core::family::AssemblerContext;
use crate::core::imagestore::ImageStore;
use crate::core::macro_processor::MacroProcessor;
use crate::core::parser as asm_parser;
use crate::core::parser::{AssignOp, Expr, Label, LineAst, ParseError};
use crate::core::preprocess::Preprocessor;
use crate::core::registry::{ModuleRegistry, RegistryError};
use crate::core::symbol_table::{ImportResult, ModuleImport, SymbolTable, SymbolVisibility};
use crate::core::text_encoding::TextEncodingRegistry;
use crate::core::token_value::TokenValue;
use crate::core::tokenizer::{register_checker_none, ConditionalKind, RegisterChecker, Span};
#[cfg(test)]
use std::cell::Cell;
use std::sync::Arc;

use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::intel8080::module::Intel8080FamilyOperands;
use crate::families::intel8080::FamilyOperand as IntelFamilyOperand;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::opthread::builder::build_hierarchy_package_from_registry;
use crate::opthread::runtime::HierarchyExecutionModel;
use crate::opthread::token_bridge::parse_line_with_model;
use crate::z80::module::Z80CpuModule;

use cli::{
    input_base_from_path, resolve_bin_path, resolve_output_path, validate_cli, BinOutputSpec,
    BinRange, Cli,
};

// Re-export public types
pub use crate::core::assembler::error::{AsmRunError as RunError, AsmRunReport as RunReport};
pub use cli::VERSION;

const DEFAULT_MODULE_EXTENSIONS: &[&str] = &["asm", "inc"];
const OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES_ENV: &str = "OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES";
const OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV: &str = "OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES";
#[cfg(feature = "opthread-runtime-opcpu-artifact")]
const OPTHREAD_RUNTIME_PACKAGE_ARTIFACT_RELATIVE_PATH: &str =
    "target/opthread/opforge-runtime.opcpu";
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

/// Run the assembler with command-line arguments.
pub fn run() -> Result<Vec<AsmRunReport>, AsmRunError> {
    let cli = Cli::parse();
    let config = validate_cli(&cli)?;

    let mut reports = Vec::new();
    for asm_path in &cli.infiles {
        let (asm_name, input_base) = input_base_from_path(asm_path)?;
        let report = run_one(&cli, &asm_name, &input_base, &config)?;
        reports.push(report);
    }

    Ok(reports)
}

fn run_one(
    cli: &Cli,
    asm_name: &str,
    input_base: &str,
    config: &cli::CliConfig,
) -> Result<AsmRunReport, AsmRunError> {
    let root_path = Path::new(asm_name);
    let root_lines = expand_source_file(root_path, &cli.defines, config.pp_macro_depth)?;
    let root_module_id = root_module_id_from_lines(root_path, &root_lines)?;
    let graph = load_module_graph(root_path, root_lines, &cli.defines, config.pp_macro_depth)?;
    let expanded_lines = Arc::new(graph.lines);

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some(root_module_id);
    assembler.module_macro_names = graph.module_macro_names;
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
    let effective_default_outputs = config.default_outputs && !meta_outputs_requested;
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
        config.out_dir.as_ref(),
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
    if config.go_addr.is_some() && hex_path.is_none() {
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
    let generated_output = assembler.image().entries().map_err(|err| {
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        )
    })?;
    if let Err(err) = listing.footer_with_generated_output(
        &pass2,
        assembler.symbols(),
        assembler.image().num_entries(),
        &generated_output,
    ) {
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
        if let Err(err) = assembler
            .image()
            .write_hex_file(&mut hex_file, config.go_addr.as_deref())
        {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                expanded_lines.clone(),
            ));
        }
    }

    let effective_bin_specs = if !config.bin_specs.is_empty() {
        config.bin_specs.to_vec()
    } else {
        output_config.bin_specs.clone()
    };
    let effective_fill_byte = if config.fill_byte_set {
        config.fill_byte
    } else {
        output_config.fill_byte.unwrap_or(config.fill_byte)
    };
    if config.fill_byte_set && effective_bin_specs.is_empty() {
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
    let mut auto_range: Option<Option<(u32, u32)>> = None;
    for (index, spec) in effective_bin_specs.iter().enumerate() {
        let range = match &spec.range {
            Some(range) => Some(range.clone()),
            None => {
                if auto_range.is_none() {
                    auto_range = Some(assembler.image().output_range().map_err(|err| {
                        AsmRunError::new(
                            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                            assembler.take_diagnostics(),
                            expanded_lines.clone(),
                        )
                    })?);
                }
                auto_range
                    .as_ref()
                    .and_then(|value| value.as_ref().copied())
                    .map(|(start, end)| BinRange {
                        start_str: format_addr(start),
                        start,
                        end,
                    })
            }
        };
        let bin_name = resolve_bin_path(
            &out_base,
            spec.name.as_deref(),
            range.as_ref(),
            bin_count,
            index,
        );
        bin_outputs.push((bin_name, range));
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
        if let Some(range) = range {
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
    }

    if let Err(err) = emit_linker_outputs(
        &assembler.root_metadata.linker_outputs,
        assembler.sections(),
        config.out_dir.as_ref(),
    ) {
        return Err(AsmRunError::new(
            err,
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }
    if let Err(err) = emit_export_sections(
        &assembler.root_metadata.export_sections,
        assembler.sections(),
        config.out_dir.as_ref(),
    ) {
        return Err(AsmRunError::new(
            err,
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }
    if let Err(err) = emit_mapfiles(
        &assembler.root_metadata.mapfiles,
        assembler.regions(),
        assembler.sections(),
        assembler.symbols(),
        config.out_dir.as_ref(),
    ) {
        return Err(AsmRunError::new(
            err,
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }

    Ok(AsmRunReport::new(
        assembler.take_diagnostics(),
        expanded_lines,
    ))
}

#[derive(Debug, Clone)]
struct ResolvedLinkerSection {
    name: String,
    base: u32,
    bytes: Vec<u8>,
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

fn collect_linker_sections(
    output: &LinkerOutputDirective,
    sections: &HashMap<String, SectionState>,
) -> Result<Vec<ResolvedLinkerSection>, AsmError> {
    let mut resolved = Vec::with_capacity(output.sections.len());
    for section_name in &output.sections {
        let Some(section) = sections.get(section_name) else {
            return Err(AsmError::new(
                AsmErrorKind::Directive,
                "Unknown section referenced by .output",
                Some(section_name),
            ));
        };
        let Some(base) = section.base_addr else {
            return Err(AsmError::new(
                AsmErrorKind::Directive,
                "Section referenced by .output must be explicitly placed",
                Some(section_name),
            ));
        };
        resolved.push(ResolvedLinkerSection {
            name: section_name.clone(),
            base,
            bytes: section.bytes.clone(),
        });
    }
    resolved.sort_by_key(|section| section.base);
    Ok(resolved)
}

fn build_linker_output_payload(
    output: &LinkerOutputDirective,
    sections: &HashMap<String, SectionState>,
) -> Result<Vec<u8>, AsmError> {
    let ordered = collect_linker_sections(output, sections)?;
    let mut payload =
        if let (Some(image_start), Some(image_end)) = (output.image_start, output.image_end) {
            let Some(fill) = output.fill else {
                return Err(AsmError::new(
                    AsmErrorKind::Directive,
                    "image output requires fill in .output",
                    None,
                ));
            };
            let span_len = image_end
                .checked_sub(image_start)
                .and_then(|delta| delta.checked_add(1))
                .ok_or_else(|| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Invalid image span range in .output",
                        Some(&output.path),
                    )
                })?;
            let image_len = usize::try_from(span_len).map_err(|_| {
                AsmError::new(
                    AsmErrorKind::Directive,
                    "Image span is too large for this host",
                    Some(&output.path),
                )
            })?;
            let mut image = vec![fill; image_len];
            for section in &ordered {
                if section.bytes.is_empty() {
                    continue;
                }
                let section_len_u32 = u32::try_from(section.bytes.len()).map_err(|_| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Section size is too large for address arithmetic in .output",
                        Some(&section.name),
                    )
                })?;
                let start = section.base;
                let end = start.checked_add(section_len_u32 - 1).ok_or_else(|| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Section address range overflows in .output",
                        Some(&section.name),
                    )
                })?;
                if start < image_start || end > image_end {
                    return Err(AsmError::new(
                        AsmErrorKind::Directive,
                        "Section falls outside image span in .output",
                        Some(&section.name),
                    ));
                }
                let offset_u32 = start.checked_sub(image_start).ok_or_else(|| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Section falls outside image span in .output",
                        Some(&section.name),
                    )
                })?;
                let offset = usize::try_from(offset_u32).map_err(|_| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Image offset is too large for this host",
                        Some(&section.name),
                    )
                })?;
                let end_offset = offset.checked_add(section.bytes.len()).ok_or_else(|| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Image offset arithmetic overflow in .output",
                        Some(&section.name),
                    )
                })?;
                if end_offset > image.len() {
                    return Err(AsmError::new(
                        AsmErrorKind::Directive,
                        "Section falls outside image span in .output",
                        Some(&section.name),
                    ));
                }
                image[offset..end_offset].copy_from_slice(&section.bytes);
            }
            image
        } else {
            if output.contiguous {
                let mut expected_base: Option<u32> = None;
                for section in ordered.iter().filter(|section| !section.bytes.is_empty()) {
                    let base = section.base;
                    let section_len_u32 = u32::try_from(section.bytes.len()).map_err(|_| {
                        AsmError::new(
                            AsmErrorKind::Directive,
                            "Section size is too large for address arithmetic in .output",
                            Some(&section.name),
                        )
                    })?;
                    if let Some(expected) = expected_base {
                        if base != expected {
                            let message = if base > expected {
                                format!(
                                    "contiguous output requires adjacent sections; gap ${}..${}",
                                    format_addr(expected),
                                    format_addr(base - 1)
                                )
                            } else {
                                format!(
                                "contiguous output requires adjacent sections; overlap ${}..${}",
                                format_addr(base),
                                format_addr(expected - 1)
                            )
                            };
                            return Err(AsmError::new(
                                AsmErrorKind::Directive,
                                &message,
                                Some(&section.name),
                            ));
                        }
                    }
                    expected_base = Some(base.checked_add(section_len_u32).ok_or_else(|| {
                        AsmError::new(
                            AsmErrorKind::Directive,
                            "Section address range overflows in contiguous output",
                            Some(&section.name),
                        )
                    })?);
                }
            }
            let total_len = ordered.iter().try_fold(0usize, |acc, section| {
                acc.checked_add(section.bytes.len()).ok_or_else(|| {
                    AsmError::new(
                        AsmErrorKind::Directive,
                        "Output payload is too large for this host",
                        Some(&output.path),
                    )
                })
            })?;
            let mut data = Vec::with_capacity(total_len);
            for section in &ordered {
                data.extend_from_slice(&section.bytes);
            }
            data
        };

    if output.format == LinkerOutputFormat::Prg {
        let loadaddr32 = output.loadaddr.unwrap_or_else(|| {
            ordered
                .iter()
                .find(|section| !section.bytes.is_empty())
                .or_else(|| ordered.first())
                .map(|section| section.base)
                .unwrap_or(0)
        });
        let loadaddr = match u16::try_from(loadaddr32) {
            Ok(v) => v,
            Err(_) => {
                return Err(AsmError::new(
                    AsmErrorKind::Directive,
                    "PRG load address exceeds 16-bit range",
                    Some(&output.path),
                ))
            }
        };
        let mut prg = Vec::with_capacity(payload.len() + 2);
        prg.push((loadaddr & 0x00ff) as u8);
        prg.push((loadaddr >> 8) as u8);
        prg.append(&mut payload);
        return Ok(prg);
    }

    Ok(payload)
}

fn resolve_linker_output_path(path: &str, out_dir: Option<&PathBuf>) -> PathBuf {
    let raw_path = PathBuf::from(path);
    if raw_path.is_absolute() {
        raw_path
    } else if let Some(dir) = out_dir {
        dir.join(raw_path)
    } else {
        raw_path
    }
}

fn emit_linker_outputs(
    outputs: &[LinkerOutputDirective],
    sections: &HashMap<String, SectionState>,
    out_dir: Option<&PathBuf>,
) -> Result<(), AsmError> {
    for output in outputs {
        let payload = build_linker_output_payload(output, sections)?;
        let output_path = resolve_linker_output_path(&output.path, out_dir);
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(err) = fs::create_dir_all(parent) {
                    let path_text = output_path.to_string_lossy().to_string();
                    return Err(AsmError::new(
                        AsmErrorKind::Io,
                        &err.to_string(),
                        Some(&path_text),
                    ));
                }
            }
        }
        let mut file = match File::create(&output_path) {
            Ok(file) => file,
            Err(err) => {
                let path_text = output_path.to_string_lossy().to_string();
                return Err(AsmError::new(
                    AsmErrorKind::Io,
                    &err.to_string(),
                    Some(&path_text),
                ));
            }
        };
        if let Err(err) = file.write_all(&payload) {
            let path_text = output_path.to_string_lossy().to_string();
            return Err(AsmError::new(
                AsmErrorKind::Io,
                &err.to_string(),
                Some(&path_text),
            ));
        }
    }
    Ok(())
}

fn build_export_sections_payloads(
    directive: &ExportSectionsDirective,
    sections: &HashMap<String, SectionState>,
) -> Vec<(String, Vec<u8>)> {
    let mut names: Vec<&String> = sections.keys().collect();
    names.sort();

    let mut outputs = Vec::new();
    for name in names {
        let section = &sections[name];
        if directive.include == ExportSectionsInclude::NoBss && section.is_bss() {
            continue;
        }
        let mut filename = name.clone();
        filename.push_str(".bin");
        outputs.push((filename, section.bytes.clone()));
    }
    outputs
}

fn emit_export_sections(
    directives: &[ExportSectionsDirective],
    sections: &HashMap<String, SectionState>,
    out_dir: Option<&PathBuf>,
) -> Result<(), AsmError> {
    for directive in directives {
        let target_dir = resolve_linker_output_path(&directive.dir, out_dir);
        if let Err(err) = fs::create_dir_all(&target_dir) {
            let dir_text = target_dir.to_string_lossy().to_string();
            return Err(AsmError::new(
                AsmErrorKind::Io,
                &err.to_string(),
                Some(&dir_text),
            ));
        }
        for (filename, payload) in build_export_sections_payloads(directive, sections) {
            let path = target_dir.join(filename);
            let mut file = match File::create(&path) {
                Ok(file) => file,
                Err(err) => {
                    let path_text = path.to_string_lossy().to_string();
                    return Err(AsmError::new(
                        AsmErrorKind::Io,
                        &err.to_string(),
                        Some(&path_text),
                    ));
                }
            };
            if let Err(err) = file.write_all(&payload) {
                let path_text = path.to_string_lossy().to_string();
                return Err(AsmError::new(
                    AsmErrorKind::Io,
                    &err.to_string(),
                    Some(&path_text),
                ));
            }
        }
    }
    Ok(())
}

fn section_kind_name(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::Code => "code",
        SectionKind::Data => "data",
        SectionKind::Bss => "bss",
    }
}

fn build_mapfile_text(
    directive: &MapFileDirective,
    regions: &HashMap<String, RegionState>,
    sections: &HashMap<String, SectionState>,
    symbols: &SymbolTable,
) -> String {
    let mut out = String::new();

    out.push_str("Regions\n");
    out.push_str("name start end used free align\n");
    let mut region_names: Vec<&String> = regions.keys().collect();
    region_names.sort();
    for name in region_names {
        let region = &regions[name];
        let capacity = u64::from(region.end)
            .checked_sub(u64::from(region.start))
            .and_then(|delta| delta.checked_add(1))
            .unwrap_or(0);
        let used = u64::from(region.cursor)
            .saturating_sub(u64::from(region.start))
            .min(capacity);
        let free = capacity.saturating_sub(used);
        out.push_str(&format!(
            "{} {} {} {} {} {}\n",
            region.name,
            format_addr(region.start),
            format_addr(region.end),
            used,
            free,
            region.align
        ));
    }
    out.push('\n');

    out.push_str("Sections\n");
    out.push_str("name base size kind region\n");
    let mut section_region: HashMap<String, String> = HashMap::new();
    for region in regions.values() {
        for placed in &region.placed {
            section_region.insert(placed.name.clone(), region.name.clone());
        }
    }
    let mut section_names: Vec<&String> = sections.keys().collect();
    section_names.sort();
    for name in section_names {
        let section = &sections[name];
        let base_text = section
            .base_addr
            .map(format_addr)
            .unwrap_or_else(|| "----".to_string());
        let region_name = section_region
            .get(name.as_str())
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{} {} {} {} {}\n",
            name,
            base_text,
            section.size_bytes(),
            section_kind_name(section.kind),
            region_name
        ));
    }

    if directive.symbols != MapSymbolsMode::None {
        out.push('\n');
        out.push_str("Symbols\n");
        out.push_str("name value visibility\n");

        let mut entries: Vec<&crate::core::symbol_table::SymbolTableEntry> =
            symbols.entries().iter().collect();
        entries.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        });
        for entry in entries {
            if directive.symbols == MapSymbolsMode::Public
                && entry.visibility != SymbolVisibility::Public
            {
                continue;
            }
            let visibility = match entry.visibility {
                SymbolVisibility::Public => "public",
                SymbolVisibility::Private => "private",
            };
            out.push_str(&format!(
                "{} {} {}\n",
                entry.name,
                format_addr(entry.val),
                visibility
            ));
        }
    }

    out
}

fn emit_mapfiles(
    directives: &[MapFileDirective],
    regions: &HashMap<String, RegionState>,
    sections: &HashMap<String, SectionState>,
    symbols: &SymbolTable,
    out_dir: Option<&PathBuf>,
) -> Result<(), AsmError> {
    for directive in directives {
        let map_text = build_mapfile_text(directive, regions, sections, symbols);
        let output_path = resolve_linker_output_path(&directive.path, out_dir);
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(err) = fs::create_dir_all(parent) {
                    let path_text = output_path.to_string_lossy().to_string();
                    return Err(AsmError::new(
                        AsmErrorKind::Io,
                        &err.to_string(),
                        Some(&path_text),
                    ));
                }
            }
        }
        if let Err(err) = fs::write(&output_path, map_text) {
            let path_text = output_path.to_string_lossy().to_string();
            return Err(AsmError::new(
                AsmErrorKind::Io,
                &err.to_string(),
                Some(&path_text),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct EncodingScopeState {
    definition_name: String,
    previous_active_encoding: String,
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
    regions: HashMap<String, RegionState>,
    placement_directives: Vec<PlacementDirective>,
    section_symbol_sections: HashMap<String, String>,
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
    start_addr: u32,
    aux_value: u32,
    pass: u8,
    label: Option<String>,
    mnemonic: Option<String>,
    cpu: CpuType,
    register_checker: RegisterChecker,
    cpu_program_address_max: u32,
    cpu_word_size_bytes: u32,
    cpu_little_endian: bool,
    cpu_state_flags: HashMap<String, u32>,
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
            regions: HashMap::new(),
            placement_directives: Vec::new(),
            section_symbol_sections: HashMap::new(),
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
            register_checker: Self::build_register_checker(registry, cpu),
            cpu_program_address_max: Self::build_cpu_program_address_max(registry, cpu),
            cpu_word_size_bytes: Self::build_cpu_word_size(registry, cpu),
            cpu_little_endian: Self::build_cpu_endianness(registry, cpu),
            cpu_state_flags: Self::build_cpu_runtime_state(registry, cpu),
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
        Self::parse_family_list_from_env(OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES_ENV)
    }

    fn expr_eval_force_host_families_from_env() -> Vec<String> {
        Self::parse_family_list_from_env(OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES_ENV)
    }

    fn portable_expr_runtime_enabled_for_family(&self, family_id: &str) -> bool {
        crate::opthread::rollout::portable_expr_runtime_enabled_for_family(
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

        #[cfg(feature = "opthread-runtime-opcpu-artifact")]
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

    #[cfg(feature = "opthread-runtime-opcpu-artifact")]
    fn opthread_package_artifact_path_for_dir(base_dir: &Path) -> PathBuf {
        base_dir.join(OPTHREAD_RUNTIME_PACKAGE_ARTIFACT_RELATIVE_PATH)
    }

    #[cfg(feature = "opthread-runtime-opcpu-artifact")]
    fn opthread_package_artifact_path() -> Option<PathBuf> {
        std::env::current_dir()
            .ok()
            .map(|base_dir| Self::opthread_package_artifact_path_for_dir(base_dir.as_path()))
    }

    #[cfg(feature = "opthread-runtime-opcpu-artifact")]
    fn load_opthread_execution_model_from_artifact(path: &Path) -> Option<HierarchyExecutionModel> {
        let bytes = fs::read(path).ok()?;
        HierarchyExecutionModel::from_package_bytes(bytes.as_slice()).ok()
    }

    #[cfg(feature = "opthread-runtime-opcpu-artifact")]
    fn persist_opthread_package_artifact(path: &Path, package_bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, package_bytes);
    }

    fn take_root_metadata(&mut self) -> RootMetadata {
        std::mem::take(&mut self.root_metadata)
    }

    fn take_placement_directives(&mut self) -> Vec<PlacementDirective> {
        std::mem::take(&mut self.placement_directives)
    }

    fn take_sections(&mut self) -> HashMap<String, SectionState> {
        std::mem::take(&mut self.sections)
    }

    fn take_regions(&mut self) -> HashMap<String, RegionState> {
        std::mem::take(&mut self.regions)
    }

    fn finalize_section_symbol_addresses(&mut self) -> Vec<AsmError> {
        let section_symbols = std::mem::take(&mut self.section_symbol_sections);
        let mut errors = Vec::new();
        let cpu_name = self.cpu.as_str().to_string();
        for (symbol_name, section_name) in section_symbols {
            let Some(base_addr) = self.sections.get(&section_name).and_then(|s| s.base_addr) else {
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
        self.scope_stack.clear();
        self.visibility_stack.clear();
        self.visibility_stack.push(SymbolVisibility::Private);
        self.module_active = None;
        self.module_scope_depth = 0;
        self.in_meta_block = false;
        self.in_output_block = false;
        self.output_cpu_block = None;
        self.sections.clear();
        self.regions.clear();
        self.placement_directives.clear();
        self.section_symbol_sections.clear();
        self.section_stack.clear();
        self.current_section = None;
        self.saw_explicit_module = false;
        self.top_level_content_seen = false;
        self.reset_cpu_runtime_profile();
        self.reset_text_encoding_profile();
    }

    fn reset_cpu_runtime_profile(&mut self) {
        self.cpu_program_address_max = Self::build_cpu_program_address_max(self.registry, self.cpu);
        self.cpu_word_size_bytes = Self::build_cpu_word_size(self.registry, self.cpu);
        self.cpu_little_endian = Self::build_cpu_endianness(self.registry, self.cpu);
        self.cpu_state_flags = Self::build_cpu_runtime_state(self.registry, self.cpu);
    }

    fn reset_text_encoding_profile(&mut self) {
        self.active_text_encoding = self
            .text_encoding_registry
            .default_encoding_name()
            .to_string();
        self.encoding_scope_stack.clear();
    }

    fn has_open_encoding_scope(&self) -> bool {
        !self.encoding_scope_stack.is_empty()
    }

    fn current_encoding_definition_name(&self) -> Option<&str> {
        self.encoding_scope_stack
            .last()
            .map(|scope| scope.definition_name.as_str())
    }

    fn begin_encode_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn end_encode_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn cdef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn tdef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn edef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn set_text_encoding_directive_ast(
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

    fn encoding_name_operand(
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

    fn byte_operand(&self, expr: &Expr, directive_name: &str) -> Result<(u8, Span), AstEvalError> {
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

    fn source_byte_operand(
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

    fn string_literal_operand(
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

    fn expr_text_value_core(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(value, _) | Expr::Register(value, _) | Expr::Number(value, _) => {
                Some(value.clone())
            }
            Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => None,
        }
    }

    fn encode_text_bytes(
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

    fn parse_text_operand(
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

    fn text_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn null_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn ptext_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

    fn apply_cpu_runtime_state_after_encode(
        &mut self,
        cpu_handler: &dyn crate::core::registry::CpuHandlerDyn,
        mnemonic: &str,
        operands: &dyn crate::core::registry::OperandSet,
    ) {
        cpu_handler.update_runtime_state_after_encode(
            mnemonic,
            operands,
            &mut self.cpu_state_flags,
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
        let mut state_flags = std::mem::take(&mut self.cpu_state_flags);
        let result =
            pipeline
                .cpu
                .apply_runtime_directive(directive, operands, self, &mut state_flags);
        self.cpu_state_flags = state_flags;
        result
    }

    fn opthread_form_allows_mnemonic(
        &self,
        pipeline: &crate::core::registry::ResolvedPipeline<'_>,
        mapped_mnemonic: &str,
    ) -> Result<bool, String> {
        if !crate::opthread::rollout::package_runtime_default_enabled_for_family(
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
        self.module_active.is_some()
    }

    fn in_section(&self) -> bool {
        self.current_section.is_some()
    }

    fn current_section_name(&self) -> Option<&str> {
        self.current_section.as_deref()
    }

    fn current_addr(&mut self, main_addr: u32) -> Result<u32, ()> {
        match self.current_section.as_deref() {
            Some(name) => {
                let Some(section) = self.sections.get(name) else {
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
                        self.last_error =
                            Some(AsmError::new(AsmErrorKind::Directive, &message, None));
                        self.last_error_column = None;
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
        if let Some(section_name) = self.current_section.as_ref() {
            self.section_symbol_sections
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
        if let Some(section_name) = self.current_section.clone() {
            let update_result: Result<(), String> = (|| {
                let Some(section) = self.sections.get_mut(&section_name) else {
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
        self.last_error = Some(AsmError::new(AsmErrorKind::Directive, &message, None));
        self.last_error_column = self.line_end_span.map(|span| span.col_start);
        Err(())
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
    fn process_with_runtime_tokenizer(&mut self, line: &str, line_num: u32) -> LineStatus {
        let model = match self.opthread_execution_model.as_ref() {
            Some(model) => model,
            None => {
                let family_id = Self::resolve_pipeline_for_cpu(self.registry, self.cpu)
                    .map(|pipeline| pipeline.family_id.as_str().to_string())
                    .unwrap_or_else(|_| self.cpu.as_str().to_string());
                let err = ParseError {
                    message: format!(
                        "opThread runtime tokenizer model unavailable for family '{}'",
                        family_id
                    ),
                    span: Span {
                        line: line_num,
                        col_start: 1,
                        col_end: 1,
                    },
                };
                self.last_error = Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.last_error_column = Some(err.span.col_start);
                self.last_parser_error = Some(err);
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
                self.last_error = Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.last_error_column = Some(err.span.col_start);
                self.last_parser_error = Some(err);
                return LineStatus::Error;
            }
        };

        self.line_end_span = Some(end_span);
        self.line_end_token = end_token_text;
        self.process_ast(ast)
    }

    fn process(&mut self, line: &str, line_num: u32, addr: u32, pass: u8) -> LineStatus {
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
                self.module_active.as_deref(),
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

    fn process_instruction_ast(&mut self, mnemonic: &str, operands: &[Expr]) -> LineStatus {
        let pipeline = match Self::resolve_pipeline_for_cpu(self.registry, self.cpu) {
            Ok(pipeline) => pipeline,
            Err(message) => {
                return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &message, None)
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

        let family_runtime_authoritative =
            crate::opthread::rollout::package_runtime_default_enabled_for_family(
                pipeline.family_id.as_str(),
            );

        {
            let allow = match self.opthread_form_allows_mnemonic(&pipeline, &mapped_mnemonic) {
                Ok(allow) => allow,
                Err(message) => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &message,
                        None,
                    )
                }
            };
            if !allow {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &format!("No instruction found for {}", mnemonic.to_ascii_uppercase()),
                    None,
                );
            }

            if self.opthread_execution_model.is_none() && family_runtime_authoritative {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &format!(
                        "opThread runtime model unavailable for authoritative family '{}'",
                        pipeline.family_id.as_str()
                    ),
                    None,
                );
            }
            if let Some(model) = self.opthread_execution_model.as_ref() {
                let runtime_expr_force_host =
                    self.portable_expr_runtime_force_host_for_family(pipeline.family_id.as_str());
                let strict_runtime_parse_resolve =
                    model.expr_resolution_is_strict_for_family(pipeline.family_id.as_str());
                let runtime_expr_bytes_authoritative = (strict_runtime_parse_resolve
                    || family_runtime_authoritative)
                    && !runtime_expr_force_host;
                // Keep this alias explicit even though it currently equals
                // `runtime_expr_bytes_authoritative`: selector-gate and VM-path
                // rollout can diverge in the future without changing call sites.
                let runtime_expr_vm_path_enabled = runtime_expr_bytes_authoritative;
                let runtime_expr_selector_gate_only = runtime_expr_vm_path_enabled
                    && model.selector_gate_only_expr_runtime_for_cpu(self.cpu.as_str());
                if runtime_expr_vm_path_enabled {
                    let runtime_expr_operands_storage =
                        Self::opthread_runtime_expr_operands_from_mapped(mapped_operands.as_ref());
                    let runtime_expr_operands =
                        runtime_expr_operands_storage.as_deref().unwrap_or(operands);
                    match model.encode_instruction_from_exprs(
                        self.cpu.as_str(),
                        None,
                        &mapped_mnemonic,
                        runtime_expr_operands,
                        self,
                    ) {
                        Ok(Some(bytes)) => {
                            if runtime_expr_selector_gate_only {
                                // Keep selector strictness checks, but defer final emission to
                                // runtime VM encode over native-resolved operands for 65816.
                            } else if bytes.is_empty() {
                                if family_runtime_authoritative {
                                    return self.failure(
                                        LineStatus::Error,
                                        AsmErrorKind::Instruction,
                                        &format!(
                                            "opThread VM program emitted no bytes for {}",
                                            mapped_mnemonic.to_ascii_uppercase()
                                        ),
                                        None,
                                    );
                                }
                                // Treat empty runtime output as no emission and continue
                                // into native resolution/encoding.
                            } else if !runtime_expr_bytes_authoritative {
                                // Staged/non-strict families keep native resolution as the source
                                // of truth for emission parity.
                            } else {
                                if let Err(err) = self.validate_instruction_emit_span(
                                    &mapped_mnemonic,
                                    operands,
                                    bytes.len(),
                                ) {
                                    return self.failure_at_span(
                                        LineStatus::Error,
                                        AsmErrorKind::Instruction,
                                        err.error.message(),
                                        None,
                                        err.span,
                                    );
                                }
                                self.bytes.extend_from_slice(&bytes);
                                if let Ok(resolved_operands) = pipeline.cpu.resolve_operands(
                                    mnemonic,
                                    mapped_operands.as_ref(),
                                    self,
                                ) {
                                    self.apply_cpu_runtime_state_after_encode(
                                        pipeline.cpu.as_ref(),
                                        &mapped_mnemonic,
                                        resolved_operands.as_ref(),
                                    );
                                }
                                return LineStatus::Ok;
                            }
                        }
                        Ok(None) => {
                            let defer_to_native_diagnostics = model
                                .defer_native_diagnostics_on_expr_none(pipeline.family_id.as_str());
                            if strict_runtime_parse_resolve && !defer_to_native_diagnostics {
                                return self.failure(
                                    LineStatus::Error,
                                    AsmErrorKind::Instruction,
                                    &format!(
                                        "No instruction found for {}",
                                        mapped_mnemonic.to_ascii_uppercase()
                                    ),
                                    None,
                                );
                            }
                        }
                        Err(err) => {
                            if !runtime_expr_selector_gate_only {
                                return self.failure(
                                    LineStatus::Error,
                                    AsmErrorKind::Instruction,
                                    &err.to_string(),
                                    None,
                                );
                            }
                        }
                    }
                }
            }
        }

        match pipeline.family.encode_family_operands(
            &mapped_mnemonic,
            mnemonic,
            mapped_operands.as_ref(),
            self,
        ) {
            crate::core::family::FamilyEncodeResult::Ok(bytes) => {
                if let Err(err) =
                    self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        err.error.message(),
                        None,
                        err.span,
                    );
                }
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

        if let Some(model) = self.opthread_execution_model.as_ref() {
            let strict_runtime_vm_programs = family_runtime_authoritative
                || model.expr_resolution_is_strict_for_family(pipeline.family_id.as_str());
            match model.encode_instruction(
                self.cpu.as_str(),
                None,
                &mapped_mnemonic,
                resolved_operands.as_ref(),
            ) {
                Ok(Some(bytes)) => {
                    if bytes.is_empty() {
                        if family_runtime_authoritative {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Instruction,
                                &format!(
                                    "opThread VM program emitted no bytes for {}",
                                    mapped_mnemonic.to_ascii_uppercase()
                                ),
                                None,
                            );
                        }
                        // Treat empty runtime output as no emission and continue
                        // into native family/cpu encoding.
                    } else {
                        if let Err(err) = self.validate_instruction_emit_span(
                            &mapped_mnemonic,
                            operands,
                            bytes.len(),
                        ) {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Instruction,
                                err.error.message(),
                                None,
                                err.span,
                            );
                        }
                        self.bytes.extend_from_slice(&bytes);
                        self.apply_cpu_runtime_state_after_encode(
                            pipeline.cpu.as_ref(),
                            &mapped_mnemonic,
                            resolved_operands.as_ref(),
                        );
                        return LineStatus::Ok;
                    }
                }
                Ok(None) => {
                    if strict_runtime_vm_programs {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &format!(
                                "missing opThread VM program for {}",
                                mapped_mnemonic.to_ascii_uppercase()
                            ),
                            None,
                        );
                    }
                }
                Err(err) => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.to_string(),
                        None,
                    );
                }
            }
        }

        match pipeline
            .family
            .encode_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
            .into_outcome()
        {
            Ok(Some(bytes)) => {
                if let Err(err) =
                    self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        err.error.message(),
                        None,
                        err.span,
                    );
                }
                self.bytes.extend_from_slice(&bytes);
                self.apply_cpu_runtime_state_after_encode(
                    pipeline.cpu.as_ref(),
                    &mapped_mnemonic,
                    resolved_operands.as_ref(),
                );
                LineStatus::Ok
            }
            Err(err) => {
                if let Some(span) = err.span {
                    self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.message,
                        None,
                        span,
                    )
                } else {
                    self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.message,
                        None,
                    )
                }
            }
            Ok(None) => match pipeline
                .cpu
                .encode_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
                .into_outcome()
            {
                Ok(Some(bytes)) => {
                    if let Err(err) =
                        self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                    {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            err.error.message(),
                            None,
                            err.span,
                        );
                    }
                    self.bytes.extend_from_slice(&bytes);
                    self.apply_cpu_runtime_state_after_encode(
                        pipeline.cpu.as_ref(),
                        &mapped_mnemonic,
                        resolved_operands.as_ref(),
                    );
                    LineStatus::Ok
                }
                Err(err) => {
                    if let Some(span) = err.span {
                        self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &err.message,
                            None,
                            span,
                        )
                    } else {
                        self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &err.message,
                            None,
                        )
                    }
                }
                Ok(None) => self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &format!("No instruction found for {}", mnemonic.to_ascii_uppercase()),
                    None,
                ),
            },
        }
    }

    fn current_section_kind(&self) -> Option<SectionKind> {
        self.current_section
            .as_ref()
            .and_then(|name| self.sections.get(name))
            .map(|section| section.kind)
    }

    fn max_program_address(&self) -> u32 {
        self.cpu_program_address_max
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
        self.cpu_little_endian
    }

    fn cpu_word_size_bytes(&self) -> u32 {
        self.cpu_word_size_bytes
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
                    self.eval_expr_for_data_directive(unit)
                }
            }
            _ => self.eval_expr_for_data_directive(unit),
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
        let count = match self.eval_expr_for_data_directive(&operands[1]) {
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
        let count = match self.eval_expr_for_data_directive(&operands[1]) {
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

    fn eval_expr_ast(&self, expr: &Expr) -> Result<u32, AstEvalError> {
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
                if crate::opthread::rollout::package_runtime_default_enabled_for_family(
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
        self.cpu_state_flags.get(key).copied()
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
