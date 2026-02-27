use super::{
    build_export_sections_payloads, build_linker_output_payload, build_mapfile_text,
    capabilities_report, capabilities_report_json, cpusupport_report, cpusupport_report_json,
    expand_source_file, load_module_graph, root_module_id_from_lines, run_with_cli,
    set_host_expr_eval_failpoint_for_tests, AsmErrorKind, AsmLine, Assembler, ExportSectionsFormat,
    ExportSectionsInclude, LineStatus, LinkerOutputDirective, LinkerOutputFormat, ListingWriter,
    MapFileDirective, MapSymbolsMode, RegionState, RootMetadata, SectionState, Severity,
};
use crate::assembler::cli::Cli;
use crate::assembler::VERSION;
use crate::core::assembler::error::{AsmError, Diagnostic};
use crate::core::macro_processor::MacroProcessor;
use crate::core::registry::ModuleRegistry;
use crate::core::symbol_table::{SymbolTable, SymbolTableResult, SymbolVisibility};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::m6800::module::Motorola6800FamilyModule;
use crate::families::mos6502::module::{
    M6502CpuModule, MOS6502FamilyModule, CPU_ID as m6502_cpu_id,
};
use crate::families::mos6502::{AddressMode, FAMILY_INSTRUCTION_TABLE};
use crate::hd6309::module::{HD6309CpuModule, CPU_ID as hd6309_cpu_id};
use crate::i8085::module::{I8085CpuModule, CPU_ID as i8085_cpu_id};
use crate::m45gs02::module::{M45GS02CpuModule, CPU_ID as m45gs02_cpu_id};
use crate::m65816::instructions::CPU_INSTRUCTION_TABLE as M65816_INSTRUCTION_TABLE;
use crate::m65816::module::M65816CpuModule;
use crate::m65816::module::CPU_ID as m65816_cpu_id;
use crate::m65c02::instructions::CPU_INSTRUCTION_TABLE as M65C02_INSTRUCTION_TABLE;
use crate::m65c02::module::{M65C02CpuModule, CPU_ID as m65c02_cpu_id};
use crate::m6809::module::{M6809CpuModule, CPU_ID as m6809_cpu_id};
use crate::vm::builder::build_hierarchy_chunks_from_registry;
use crate::vm::builder::build_hierarchy_package_from_registry;
use crate::vm::hierarchy::ScopedOwner;
use crate::vm::intel8080_vm::mode_key_for_instruction_entry;
use crate::vm::package::{
    ModeSelectorDescriptor, ParserVmOpcode, TokenizerVmOpcode, EXPR_PARSER_VM_OPCODE_VERSION_V1,
};
use crate::vm::rollout::{
    family_runtime_mode, family_runtime_rollout_policy, package_runtime_default_enabled_for_family,
    FamilyRuntimeMode,
};
use crate::vm::runtime::{
    set_core_expr_parser_failpoint_for_tests, HierarchyExecutionModel, PortableSpan, PortableToken,
    PortableTokenKind,
};
use crate::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
use crate::z80::module::{Z80CpuModule, CPU_ID as z80_cpu_id};
use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

fn default_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(Motorola6800FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry.register_cpu(Box::new(M6809CpuModule));
    registry.register_cpu(Box::new(HD6309CpuModule));
    registry
}

fn make_asm_line<'a>(symbols: &'a mut SymbolTable, registry: &'a ModuleRegistry) -> AsmLine<'a> {
    AsmLine::new(symbols, registry)
}

fn process_line(asm: &mut AsmLine<'_>, line: &str, addr: u32, pass: u8) -> LineStatus {
    asm.process(line, 1, addr, pass)
}

#[test]
fn runtime_token_bridge_maps_portable_tokens_to_core_tokens() {
    let runtime_tokens = vec![
        PortableToken {
            kind: PortableTokenKind::Identifier("lda".to_string()),
            span: PortableSpan {
                line: 1,
                col_start: 5,
                col_end: 8,
            },
        },
        PortableToken {
            kind: PortableTokenKind::Hash,
            span: PortableSpan {
                line: 1,
                col_start: 9,
                col_end: 10,
            },
        },
        PortableToken {
            kind: PortableTokenKind::Number {
                text: "$42".to_string(),
                base: 16,
            },
            span: PortableSpan {
                line: 1,
                col_start: 10,
                col_end: 13,
            },
        },
    ];

    let mapped = crate::vm::token_bridge::runtime_tokens_to_core_tokens(
        &runtime_tokens,
        &crate::core::tokenizer::register_checker_none(),
    )
    .expect("portable token mapping should succeed");
    assert_eq!(mapped.len(), 3);
    assert!(matches!(
        &mapped[0].kind,
        crate::core::tokenizer::TokenKind::Identifier(name) if name == "lda"
    ));
    assert!(matches!(
        &mapped[2].kind,
        crate::core::tokenizer::TokenKind::Number(num) if num.text == "$42" && num.base == 16
    ));
}

#[test]
fn runtime_token_bridge_rejects_invalid_spans() {
    let runtime_tokens = vec![PortableToken {
        kind: PortableTokenKind::Identifier("lda".to_string()),
        span: PortableSpan {
            line: 1,
            col_start: 0,
            col_end: 3,
        },
    }];

    let err = crate::vm::token_bridge::runtime_tokens_to_core_tokens(
        &runtime_tokens,
        &crate::core::tokenizer::register_checker_none(),
    )
    .expect_err("invalid spans should be rejected");
    assert!(err.message.contains("invalid token span"));
}

fn assemble_bytes(cpu: crate::core::cpu::CpuType, line: &str) -> Vec<u8> {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    assert_eq!(
        status,
        LineStatus::Ok,
        "assembly failed for '{line}' with {:?}",
        asm.error().map(|err| err.to_string())
    );
    asm.bytes().to_vec()
}

fn assemble_line_status(
    cpu: crate::core::cpu::CpuType,
    line: &str,
) -> (LineStatus, Option<String>) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message)
}

#[test]
fn regression_expression_error_is_diagnostic_not_panic() {
    let (status, message) = assemble_line_status(i8085_cpu_id, "MVI A, (1 +");
    assert_eq!(status, LineStatus::Error);
    assert!(message.is_some());
}

#[test]
fn regression_symbol_resolution_error_is_diagnostic_not_panic() {
    let (status, message) = assemble_line_status(i8085_cpu_id, "MVI A, MISSING_SYMBOL");
    assert_eq!(status, LineStatus::Error);
    assert!(message.is_some());
}

#[test]
fn regression_operand_parse_error_is_diagnostic_not_panic() {
    let (status, message) = assemble_line_status(i8085_cpu_id, "MVI A, #1");
    assert_eq!(status, LineStatus::Error);
    assert!(message.is_some());
}

fn assemble_line_with_runtime_mode(
    cpu: crate::core::cpu::CpuType,
    line: &str,
    _enable_opthread_runtime: bool,
) -> (LineStatus, Option<String>, Vec<u8>) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    if _enable_opthread_runtime {
        let enable_intel_runtime = registry
            .resolve_pipeline(cpu, None)
            .map(|pipeline| {
                pipeline
                    .family_id
                    .as_str()
                    .eq_ignore_ascii_case(crate::families::intel8080::module::FAMILY_ID.as_str())
            })
            .unwrap_or(false);
        if enable_intel_runtime {
            let package_bytes =
                build_hierarchy_package_from_registry(&registry).expect("build hierarchy package");
            asm.opthread_execution_model = Some(
                HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
                    .expect("runtime execution model from package bytes"),
            );
        }
    }
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec())
}

fn assemble_line_with_runtime_mode_no_injection(
    cpu: crate::core::cpu::CpuType,
    line: &str,
    _enable_opthread_runtime: bool,
) -> (LineStatus, Option<String>, Vec<u8>, bool) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    let has_model = asm.opthread_execution_model.is_some();
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec(), has_model)
}

fn assemble_line_diagnostic_with_runtime_mode(
    cpu: crate::core::cpu::CpuType,
    line: &str,
    enable_runtime_model: bool,
) -> (LineStatus, Option<Diagnostic>) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    if enable_runtime_model {
        let enable_intel_runtime = registry
            .resolve_pipeline(cpu, None)
            .map(|pipeline| {
                pipeline
                    .family_id
                    .as_str()
                    .eq_ignore_ascii_case(crate::families::intel8080::module::FAMILY_ID.as_str())
            })
            .unwrap_or(false);
        if enable_intel_runtime {
            let package_bytes =
                build_hierarchy_package_from_registry(&registry).expect("build hierarchy package");
            asm.opthread_execution_model = Some(
                HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
                    .expect("runtime execution model from package bytes"),
            );
        }
    }

    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let diag = asm.error().cloned().map(|err| {
        let mut diag = Diagnostic::new(
            1,
            if status == LineStatus::Warning {
                Severity::Warning
            } else {
                Severity::Error
            },
            err,
        )
        .with_column(asm.error_column())
        .with_parser_error(asm.parser_error());
        if let Some(help) = asm.error_help() {
            diag = diag.with_help(help.to_string());
        }
        for fixit in asm.error_fixits() {
            diag = diag.with_fixit(fixit.clone());
        }
        if let Some(parse_error) = asm.parser_error_ref() {
            diag = diag.with_col_end(Some(parse_error.span.col_end));
        }
        diag
    });
    (status, diag)
}

fn assemble_i8085_line_with_expr_vm_opt_in(
    line: &str,
    start_addr: u32,
    symbol_seed: Option<(u32, bool)>,
    enable_portable_expr_vm: bool,
) -> (LineStatus, Option<String>, Vec<u8>) {
    let mut symbols = SymbolTable::new();
    if let Some((value, finalized)) = symbol_seed {
        assert_eq!(
            symbols.add("target", value, false, SymbolVisibility::Private, None),
            SymbolTableResult::Ok,
            "seed symbol add should succeed"
        );
        if finalized {
            assert_eq!(
                symbols.update("target", value),
                SymbolTableResult::Ok,
                "seed symbol finalize should succeed"
            );
        }
    }

    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    if enable_portable_expr_vm {
        asm.opthread_expr_eval_opt_in_families
            .push("intel8080".to_string());
    }
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process(line, 1, start_addr, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec())
}

fn assemble_line_with_expr_vm_force_host(
    cpu: crate::core::cpu::CpuType,
    family_id: &str,
    line: &str,
    start_addr: u32,
    symbol_seed: Option<(u32, bool)>,
    force_host: bool,
) -> (LineStatus, Option<String>, Vec<u8>) {
    let mut symbols = SymbolTable::new();
    if let Some((value, finalized)) = symbol_seed {
        assert_eq!(
            symbols.add("target", value, false, SymbolVisibility::Private, None),
            SymbolTableResult::Ok,
            "seed symbol add should succeed"
        );
        if finalized {
            assert_eq!(
                symbols.update("target", value),
                SymbolTableResult::Ok,
                "seed symbol finalize should succeed"
            );
        }
    }

    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    if force_host {
        asm.opthread_expr_eval_force_host_families
            .push(family_id.to_string());
    }
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process(line, 1, start_addr, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec())
}

type AssembleEntriesResult = Result<(Vec<(u32, u8)>, Vec<String>), String>;

fn assemble_source_entries_with_runtime_mode(
    lines: &[&str],
    _enable_opthread_runtime: bool,
) -> AssembleEntriesResult {
    let mut assembler = Assembler::new();
    assembler.clear_diagnostics();

    let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
    let pass1 = assembler.pass1(&lines);
    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler
        .pass2(&lines, &mut listing)
        .map_err(|err| format!("Pass2 failed: {err}"))?;

    let entries = assembler
        .image()
        .entries()
        .map_err(|err| format!("Read generated output: {err}"))?;
    let diagnostics: Vec<String> = assembler
        .diagnostics
        .iter()
        .filter(|diag| diag.severity == Severity::Error)
        .map(|diag| format!("{}:{}", diag.line, diag.error.message()))
        .collect();

    if pass1.errors > 0 || pass2.errors > 0 {
        return Ok((entries, diagnostics));
    }
    Ok((entries, diagnostics))
}

fn assemble_example(asm_path: &Path, out_dir: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
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
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let list_path = out_dir.join(format!("{base}.lst"));
    let hex_path = out_dir.join(format!("{base}.hex"));

    let mut list_file =
        File::create(&list_path).map_err(|err| format!("Create list file: {err}"))?;
    let mut hex_file = File::create(&hex_path).map_err(|err| format!("Create hex file: {err}"))?;

    let root_path = asm_path;
    let root_lines = expand_source_file(root_path, &[], &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let graph = load_module_graph(root_path, root_lines.clone(), &[], &[], &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let expanded_lines = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id =
        Some(root_module_id_from_lines(root_path, &root_lines).map_err(|err| err.to_string())?);
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let _ = assembler.pass1(&expanded_lines);

    let mut listing = ListingWriter::new(&mut list_file, false);
    listing
        .header(&format!("opForge Assembler v{VERSION}"))
        .map_err(|err| format!("Write listing header: {err}"))?;
    let pass2 = assembler
        .pass2(&expanded_lines, &mut listing)
        .map_err(|err| format!("Pass2 failed: {err}"))?;
    let generated_output = assembler
        .image()
        .entries()
        .map_err(|err| format!("Read generated output: {err}"))?;
    listing
        .footer_with_generated_output(
            &pass2,
            assembler.symbols(),
            assembler.image().num_entries(),
            &generated_output,
        )
        .map_err(|err| format!("Write listing footer: {err}"))?;

    assembler
        .image()
        .write_hex_file(&mut hex_file, None)
        .map_err(|err| format!("Write hex file: {err}"))?;

    validate_example_linker_outputs(&assembler)?;

    let map_directives = &assembler.root_metadata.mapfiles;
    let map_outputs = map_directives
        .iter()
        .enumerate()
        .map(|(idx, directive)| {
            let map_name = if map_directives.len() == 1 {
                format!("{base}.map")
            } else {
                format!("{base}.{}.map", idx + 1)
            };
            let map = build_mapfile_text(
                directive,
                assembler.regions(),
                assembler.sections(),
                assembler.symbols(),
            );
            (map_name, map.into_bytes())
        })
        .collect();

    Ok(map_outputs)
}

fn assemble_example_entries_with_runtime_mode(
    asm_path: &Path,
    _enable_opthread_runtime: bool,
) -> AssembleEntriesResult {
    let root_lines = expand_source_file(asm_path, &[], &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let graph = load_module_graph(asm_path, root_lines.clone(), &[], &[], &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let expanded_lines = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id =
        Some(root_module_id_from_lines(asm_path, &root_lines).map_err(|err| err.to_string())?);
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();

    let pass1 = assembler.pass1(&expanded_lines);
    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler
        .pass2(&expanded_lines, &mut listing)
        .map_err(|err| format!("Pass2 failed: {err}"))?;

    let entries = assembler
        .image()
        .entries()
        .map_err(|err| format!("Read generated output: {err}"))?;
    let diagnostics: Vec<String> = assembler
        .diagnostics
        .iter()
        .filter(|diag| diag.severity == Severity::Error)
        .map(|diag| format!("{}:{}", diag.line, diag.error.message()))
        .collect();

    if pass1.errors > 0 || pass2.errors > 0 {
        return Ok((entries, diagnostics));
    }
    Ok((entries, diagnostics))
}

fn run_pass1(lines: &[&str]) -> Assembler {
    let mut assembler = Assembler::new();
    let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
    let _ = assembler.pass1(&lines);
    assembler
}

fn run_passes(lines: &[&str]) -> Assembler {
    let mut assembler = Assembler::new();
    let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0, "pass1 should succeed");
    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0, "pass2 should succeed");
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

fn validate_example_linker_outputs(assembler: &Assembler) -> Result<(), String> {
    for output in &assembler.root_metadata.linker_outputs {
        build_linker_output_payload(output, assembler.sections())
            .map_err(|err| format!("Assembly failed: {}", err.message()))?;
    }
    Ok(())
}

fn first_example_error(assembler: &Assembler, source_lines: &[String]) -> Option<String> {
    assembler
        .diagnostics
        .iter()
        .find(|diag| diag.severity == Severity::Error)
        .map(|diag| {
            format!(
                "Assembly failed:\n{}",
                diag.format_with_context(Some(source_lines), false)
            )
        })
}

fn assemble_example_error(asm_path: &Path) -> Option<String> {
    let asm_name = asm_path.to_string_lossy().to_string();

    let root_path = Path::new(&asm_name);
    let root_lines = match expand_source_file(root_path, &[], &[], 64) {
        Ok(lines) => lines,
        Err(err) => return Some(format!("Preprocess failed: {err}")),
    };
    let (expanded_lines, module_macro_names) =
        match load_module_graph(root_path, root_lines.clone(), &[], &[], &[], 64) {
            Ok(graph) => (graph.lines, graph.module_macro_names),
            Err(err) => return Some(format!("Preprocess failed: {err}")),
        };

    let mut assembler = Assembler::new();
    if let Ok(module_id) = root_module_id_from_lines(root_path, &root_lines) {
        assembler.root_metadata.root_module_id = Some(module_id);
    }
    assembler.module_macro_names = module_macro_names;
    assembler.clear_diagnostics();
    let _ = assembler.pass1(&expanded_lines);

    let mut sink = io::sink();
    let mut listing = ListingWriter::new(&mut sink, false);
    if listing
        .header(&format!("opForge Assembler v{VERSION}"))
        .is_ok()
    {
        let _ = assembler.pass2(&expanded_lines, &mut listing);
    }
    if let Err(err) = validate_example_linker_outputs(&assembler) {
        return Some(err);
    }

    first_example_error(&assembler, &expanded_lines)
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

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let combined = load_module_graph(&root_path, root_lines, &[], &[], &[], 32)
        .expect("load graph")
        .lines;

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

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let err = load_module_graph(&root_path, root_lines, &[], &[], &[], 32)
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

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let err = load_module_graph(&root_path, root_lines, &[], &[], &[], 32)
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

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let err = load_module_graph(&root_path, root_lines, &[], &[], &[], 32)
        .expect_err("expected ambiguous module id");
    assert!(
        err.to_string().contains("Ambiguous module"),
        "unexpected error: {err}"
    );
}

#[test]
fn module_loader_resolves_dependency_from_external_module_path() {
    let dir = create_temp_dir("module-path-external");
    let root_path = dir.join("main.asm");
    let ext_root = dir.join("extmods");
    fs::create_dir_all(&ext_root).expect("create external module root");

    write_file(&root_path, ".module app\n    .use lib\n.endmodule\n");
    write_file(&ext_root.join("lib.asm"), ".module lib\n.endmodule\n");

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let combined = load_module_graph(&root_path, root_lines, &[], &[], &[ext_root], 32)
        .expect("load graph from external module root")
        .lines;

    assert!(
        combined
            .iter()
            .any(|line| line.trim().eq_ignore_ascii_case(".module lib")),
        "external module should be loaded"
    );
}

#[test]
fn module_graph_source_map_tracks_dependency_and_root_origins() {
    let dir = create_temp_dir("module-source-map");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .byte 1\n.endmodule\n",
    );
    write_file(&lib_path, ".module lib\nVALUE .const 2\n.endmodule\n");

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let graph =
        load_module_graph(&root_path, root_lines, &[], &[], &[], 32).expect("load module graph");

    assert_eq!(
        graph.lines.len(),
        graph.source_map.origins().len(),
        "source map should have one origin per expanded line"
    );

    let lib_idx = graph
        .lines
        .iter()
        .position(|line| line.trim().eq_ignore_ascii_case(".module lib"))
        .expect("lib module in combined output");
    let app_idx = graph
        .lines
        .iter()
        .position(|line| line.trim().eq_ignore_ascii_case(".module app"))
        .expect("app module in combined output");

    let lib_origin = &graph.source_map.origins()[lib_idx];
    let app_origin = &graph.source_map.origins()[app_idx];
    assert_eq!(
        lib_origin.file.as_deref(),
        Some(lib_path.to_string_lossy().as_ref())
    );
    assert_eq!(
        app_origin.file.as_deref(),
        Some(root_path.to_string_lossy().as_ref())
    );
}

#[test]
fn run_with_cli_attributes_dependency_diagnostics_to_dependency_file() {
    let dir = create_temp_dir("module-diagnostic-origin");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");
    let list_path = dir.join("out.lst");
    let hex_path = dir.join("out.hex");

    write_file(&root_path, ".module app\n    .use lib\n.endmodule\n");
    write_file(&lib_path, ".module lib\n    BADOP\n.endmodule\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        root_path.to_string_lossy().as_ref(),
        "-l",
        list_path.to_string_lossy().as_ref(),
        "-x",
        hex_path.to_string_lossy().as_ref(),
    ]);

    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("assembly should fail for unknown mnemonic"),
        Err(err) => err,
    };
    assert!(
        err.diagnostics().iter().any(|diag| {
            diag.file()
                .map(|file| file.ends_with("lib.asm"))
                .unwrap_or(false)
        }),
        "expected at least one diagnostic attributed to lib.asm, got: {:?}",
        err.diagnostics()
            .iter()
            .map(|diag| (diag.file(), diag.line(), diag.message()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn run_with_cli_attributes_macro_expansion_diagnostic_to_root_file() {
    let dir = create_temp_dir("macro-diagnostic-origin");
    let root_path = dir.join("main.asm");
    let list_path = dir.join("out.lst");
    let hex_path = dir.join("out.hex");

    write_file(
        &root_path,
        "bad .macro\n    BADOP\n.endmacro\n\n.module app\n    bad\n.endmodule\n",
    );

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        root_path.to_string_lossy().as_ref(),
        "-l",
        list_path.to_string_lossy().as_ref(),
        "-x",
        hex_path.to_string_lossy().as_ref(),
    ]);

    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("assembly should fail for bad macro expansion"),
        Err(err) => err,
    };
    assert!(
        err.diagnostics().iter().any(|diag| {
            diag.file()
                .map(|file| file.ends_with("main.asm"))
                .unwrap_or(false)
        }),
        "expected at least one diagnostic attributed to main.asm, got: {:?}",
        err.diagnostics()
            .iter()
            .map(|diag| (diag.file(), diag.line(), diag.message()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn module_loader_ambiguity_reports_candidate_paths_and_roots() {
    let dir = create_temp_dir("module-path-ambiguous");
    let root_path = dir.join("main.asm");
    let ext_a = dir.join("ext_a");
    let ext_b = dir.join("ext_b");
    fs::create_dir_all(&ext_a).expect("create external root a");
    fs::create_dir_all(&ext_b).expect("create external root b");

    write_file(&root_path, ".module app\n    .use lib\n.endmodule\n");
    write_file(&ext_a.join("lib.asm"), ".module lib\n.endmodule\n");
    write_file(&ext_b.join("lib.asm"), ".module lib\n.endmodule\n");

    let root_lines = expand_source_file(&root_path, &[], &[], 32).expect("expand root");
    let err = load_module_graph(
        &root_path,
        root_lines,
        &[],
        &[],
        &[ext_a.clone(), ext_b.clone()],
        32,
    )
    .expect_err("expected module ambiguity");

    let message = err.to_string();
    assert!(
        message.contains("candidates:"),
        "missing candidates: {message}"
    );
    assert!(
        message.contains(ext_a.join("lib.asm").to_string_lossy().as_ref()),
        "missing candidate path for ext_a: {message}"
    );
    assert!(
        message.contains(ext_b.join("lib.asm").to_string_lossy().as_ref()),
        "missing candidate path for ext_b: {message}"
    );
    assert!(
        message.contains(ext_a.to_string_lossy().as_ref()),
        "missing root provenance for ext_a: {message}"
    );
    assert!(
        message.contains(ext_b.to_string_lossy().as_ref()),
        "missing root provenance for ext_b: {message}"
    );
}

#[test]
fn expand_source_file_uses_include_roots_in_cli_order() {
    let dir = create_temp_dir("include-roots-order");
    let root_path = dir.join("main.asm");
    let inc_a = dir.join("inc_a");
    let inc_b = dir.join("inc_b");

    fs::create_dir_all(&inc_a).expect("create include root a");
    fs::create_dir_all(&inc_b).expect("create include root b");
    write_file(&root_path, ".include \"defs.inc\"\n.byte VALUE\n");
    write_file(&inc_a.join("defs.inc"), "VALUE .const 10\n");
    write_file(&inc_b.join("defs.inc"), "VALUE .const 20\n");

    let lines_a_then_b = expand_source_file(&root_path, &[], &[inc_a.clone(), inc_b.clone()], 32)
        .expect("expand with include roots");
    assert!(
        lines_a_then_b
            .iter()
            .any(|line| line.contains("VALUE .const 10")),
        "first include root should win"
    );

    let lines_b_then_a = expand_source_file(&root_path, &[], &[inc_b, inc_a], 32)
        .expect("expand with swapped roots");
    assert!(
        lines_b_then_a
            .iter()
            .any(|line| line.contains("VALUE .const 20")),
        "include resolution should follow command-line order"
    );
}

#[test]
fn run_with_cli_werror_fails_when_warning_is_emitted() {
    let dir = create_temp_dir("werror-warning");
    let input = dir.join("warn.asm");
    let list = dir.join("warn.lst");
    write_file(&input, ".byte 300\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--Werror",
    ]);

    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("warnings should fail under --Werror"),
        Err(err) => err,
    };
    assert_eq!(err.to_string(), "Warnings treated as errors (-Werror)");
}

#[test]
fn run_with_cli_cpu_override_enables_non_default_instruction_set() {
    let dir = create_temp_dir("cpu-override");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "    rts\n");

    let default_cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
    ]);
    assert!(
        run_with_cli(&default_cli).is_err(),
        "default CPU should reject 6502 mnemonic"
    );

    let override_cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "m6502",
    ]);
    let report = run_with_cli(&override_cli).expect("cpu override should succeed");
    assert_eq!(report.len(), 1);
}

#[test]
fn run_with_cli_reports_unknown_cpu_override() {
    let dir = create_temp_dir("cpu-override-unknown");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "nope999",
    ]);
    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("unknown cpu should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("Unknown CPU: nope999"));
}

#[test]
fn run_with_cli_rejects_45gs02_flat_z_form_on_m6502_override() {
    let dir = create_temp_dir("cpu-override-m6502-flat-z");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "    lda ($20),z\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "m6502",
    ]);
    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("m6502 override should reject 45gs02-only flat-z form"),
        Err(err) => err,
    };
    assert!(
        err.diagnostics()
            .iter()
            .any(|diag| { diag.message().contains("No instruction found for LDA") }),
        "unexpected diagnostics: {:?}",
        err.diagnostics()
            .iter()
            .map(|diag| diag.message().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn run_with_cli_rejects_45gs02_flat_z_form_on_m65c02_override() {
    let dir = create_temp_dir("cpu-override-m65c02-flat-z");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "    lda ($20),z\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "65c02",
    ]);
    let err = match run_with_cli(&cli) {
        Ok(_) => panic!("m65c02 override should reject 45gs02-only flat-z form"),
        Err(err) => err,
    };
    assert!(
        err.diagnostics()
            .iter()
            .any(|diag| { diag.message().contains("No instruction found for LDA") }),
        "unexpected diagnostics: {:?}",
        err.diagnostics()
            .iter()
            .map(|diag| diag.message().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn run_with_cli_accepts_45gs02_alias_override() {
    let dir = create_temp_dir("cpu-override-mega65-alias");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "    adcq #$01\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "mega65",
    ]);

    let report = run_with_cli(&cli).expect("mega65 alias should resolve to 45gs02");
    assert_eq!(report.len(), 1);
}

#[test]
fn run_with_cli_accepts_45gs02_asw_and_row_forms() {
    let dir = create_temp_dir("cpu-override-45gs02-asw-row");
    let input = dir.join("cpu.asm");
    let list = dir.join("cpu.lst");
    write_file(&input, "    asw $2000\n    row $2002\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--cpu",
        "45gs02",
    ]);

    let report = run_with_cli(&cli).expect("45gs02 ASW/ROW forms should assemble");
    assert_eq!(report.len(), 1);
}

#[test]
fn run_with_cli_writes_make_dependencies_file() {
    let dir = create_temp_dir("dependencies-file");
    let input = dir.join("main.asm");
    let include = dir.join("defs.inc");
    let list = dir.join("main.lst");
    let deps = dir.join("deps.mk");
    write_file(&include, "; include dependency fixture\n");
    write_file(&input, ".include \"defs.inc\"\n    nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--dependencies",
        deps.to_string_lossy().as_ref(),
        "--make-phony",
    ]);
    run_with_cli(&cli).expect("assembly succeeds with dependency output");

    let content = fs::read_to_string(&deps).expect("read dependency file");
    assert!(
        content.contains(list.to_string_lossy().as_ref()),
        "dependency target missing list output: {content}"
    );
    assert!(
        content.contains(input.to_string_lossy().as_ref()),
        "dependency source missing root file: {content}"
    );
    assert!(
        content.contains(include.to_string_lossy().as_ref()),
        "dependency source missing include file: {content}"
    );
    assert!(
        content.contains(":"),
        "dependency rule missing colon: {content}"
    );
}

#[test]
fn run_with_cli_writes_labels_file() {
    let dir = create_temp_dir("labels-file");
    let input = dir.join("labels.asm");
    let list = dir.join("labels.lst");
    let labels = dir.join("labels.lbl");
    write_file(&input, "START: nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--labels",
        labels.to_string_lossy().as_ref(),
    ]);
    run_with_cli(&cli).expect("assembly succeeds with labels output");

    let content = fs::read_to_string(&labels).expect("read labels file");
    assert!(
        content.contains("START = $0000"),
        "missing label export: {content}"
    );
}

#[test]
fn run_with_cli_writes_vice_labels_file() {
    let dir = create_temp_dir("labels-file-vice");
    let input = dir.join("labels.asm");
    let list = dir.join("labels.lst");
    let labels = dir.join("labels.lbl");
    write_file(&input, "START: nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--labels",
        labels.to_string_lossy().as_ref(),
        "--vice-labels",
    ]);
    run_with_cli(&cli).expect("assembly succeeds with vice labels output");

    let content = fs::read_to_string(&labels).expect("read labels file");
    assert!(
        content.contains("al C:$0000 .START"),
        "missing vice label export: {content}"
    );
}

#[test]
fn run_with_cli_writes_ctags_labels_file() {
    let dir = create_temp_dir("labels-file-ctags");
    let input = dir.join("labels.asm");
    let list = dir.join("labels.lst");
    let labels = dir.join("labels.tags");
    write_file(&input, "START: nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--labels",
        labels.to_string_lossy().as_ref(),
        "--ctags-labels",
    ]);
    run_with_cli(&cli).expect("assembly succeeds with ctags labels output");

    let content = fs::read_to_string(&labels).expect("read labels file");
    assert!(
        content.contains("START\tlabels\t/^START$/;\"\tv"),
        "missing ctags label export: {content}"
    );
}

#[test]
fn run_with_cli_tab_size_expands_listing_tabs() {
    let dir = create_temp_dir("listing-tab-size");
    let input = dir.join("tabbed.asm");
    let list = dir.join("tabbed.lst");
    write_file(&input, "\tlda\t#1\n");

    let cli = Cli::parse_from([
        "opForge",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--tab-size",
        "4",
    ]);
    run_with_cli(&cli).expect("assembly succeeds with tab-size output");

    let content = fs::read_to_string(&list).expect("read listing file");
    assert!(
        content.contains("    lda #1"),
        "listing source tabs were not expanded: {content}"
    );
}

#[test]
fn capabilities_report_has_stable_header_and_features() {
    let text = capabilities_report();
    assert!(text.starts_with("opforge-capabilities-v1\n"));
    assert!(text.contains("feature=include-path"));
    assert!(text.contains("feature=dependency-output"));
    assert!(text.contains("opforge-cpusupport-v1"));
}

#[test]
fn cpusupport_report_has_stable_shape() {
    let text = cpusupport_report();
    assert!(text.starts_with("opforge-cpusupport-v1\n"));
    assert!(text.lines().any(|line| line.starts_with("cpu=8085;")));
    assert!(text.lines().any(|line| line.starts_with("cpu=m6502;")));
    assert!(text.lines().any(|line| line.starts_with("cpu=m6809;")));
    assert!(text.lines().any(|line| line.starts_with("cpu=hd6309;")));
}

#[test]
fn cpusupport_report_json_has_stable_shape() {
    let text = cpusupport_report_json();
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid cpusupport json");
    assert_eq!(value["schema"], "opforge-cpusupport-v1");
    let cpus = value["cpus"].as_array().expect("cpus array");
    assert!(cpus.iter().any(|entry| entry["cpu"] == "8085"));
    assert!(cpus.iter().any(|entry| entry["cpu"] == "m6502"));
    assert!(cpus.iter().any(|entry| entry["cpu"] == "m6809"));
    assert!(cpus.iter().any(|entry| entry["cpu"] == "hd6309"));
    assert!(cpus
        .iter()
        .all(|entry| entry.get("family").is_some() && entry.get("default_dialect").is_some()));
}

#[test]
fn capabilities_report_json_has_stable_shape() {
    let text = capabilities_report_json();
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid capabilities json");
    assert_eq!(value["schema"], "opforge-capabilities-v1");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["features"]
        .as_array()
        .expect("features array")
        .iter()
        .any(|feature| feature == "dependency-output"));
    assert_eq!(
        value["cpusupport"]["schema"], "opforge-cpusupport-v1",
        "capabilities json should embed cpu support payload"
    );
}

#[test]
fn run_with_cli_writes_labels_as_json_in_json_mode() {
    let dir = create_temp_dir("labels-file-json");
    let input = dir.join("labels_json.asm");
    let list = dir.join("labels_json.lst");
    let labels = dir.join("labels.json");
    write_file(&input, "START: nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "--format",
        "json",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--labels",
        labels.to_string_lossy().as_ref(),
    ]);
    run_with_cli(&cli).expect("assembly succeeds with json labels output");

    let content = fs::read_to_string(&labels).expect("read labels json");
    let value: serde_json::Value = serde_json::from_str(&content).expect("labels json parse");
    let labels_array = value["labels"].as_array().expect("labels array");
    assert!(labels_array.iter().any(|entry| entry["name"] == "START"));
}

#[test]
fn run_with_cli_writes_dependencies_as_json_line_in_json_mode() {
    let dir = create_temp_dir("deps-file-json");
    let input = dir.join("deps_json.asm");
    let list = dir.join("deps_json.lst");
    let deps = dir.join("deps.jsonl");
    write_file(&input, "    nop\n");

    let cli = Cli::parse_from([
        "opForge",
        "--format",
        "json",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "--dependencies",
        deps.to_string_lossy().as_ref(),
        "--make-phony",
    ]);
    run_with_cli(&cli).expect("assembly succeeds with json dependency output");

    let content = fs::read_to_string(&deps).expect("read dependencies jsonl");
    let line = content.lines().next().expect("first json line");
    let value: serde_json::Value = serde_json::from_str(line).expect("dependency json parse");
    assert!(value["targets"].is_array());
    assert!(value["dependencies"].is_array());
    assert_eq!(value["make_phony"], true);
    assert!(value["phony_targets"].is_array());
}

fn json_array_as_sorted_filenames(value: &serde_json::Value, key: &str) -> Vec<String> {
    let mut names: Vec<String> = value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} should be an array"))
        .iter()
        .map(|entry| {
            let raw = entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entry should be a string"));
            let unescaped = raw.replace("\\ ", " ");
            Path::new(&unescaped)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(unescaped.as_str())
                .to_string()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn cli_json_outputs_example_matches_reference() {
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
            .join(format!("json-output-example-{}-{}", process::id(), nanos));
    fs::create_dir_all(&out_dir).expect("create json output test directory");
    if update_reference {
        fs::create_dir_all(&reference_dir).expect("create reference directory");
    }

    let input = examples_dir.join("cli_json_outputs.asm");
    let list = out_dir.join("cli_json_outputs.lst");
    let hex = out_dir.join("cli_json_outputs.hex");
    let labels = out_dir.join("cli_json_outputs.labels.json");
    let deps = out_dir.join("cli_json_outputs.dependencies.jsonl");

    let cli = Cli::parse_from([
        "opForge",
        "--format",
        "json",
        "-i",
        input.to_string_lossy().as_ref(),
        "-l",
        list.to_string_lossy().as_ref(),
        "-x",
        hex.to_string_lossy().as_ref(),
        "--labels",
        labels.to_string_lossy().as_ref(),
        "--dependencies",
        deps.to_string_lossy().as_ref(),
        "--make-phony",
    ]);
    run_with_cli(&cli).expect("assembly succeeds for json output fixture");

    let labels_content = fs::read_to_string(&labels).expect("read labels json output");
    let labels_value: serde_json::Value =
        serde_json::from_str(&labels_content).expect("parse labels json output");

    let deps_content = fs::read_to_string(&deps).expect("read dependencies jsonl output");
    let deps_line = deps_content
        .lines()
        .next()
        .expect("dependencies json output should have one line");
    let deps_value: serde_json::Value =
        serde_json::from_str(deps_line).expect("parse dependencies json output");

    let normalized_deps = serde_json::json!({
        "targets": json_array_as_sorted_filenames(&deps_value, "targets"),
        "dependencies": json_array_as_sorted_filenames(&deps_value, "dependencies"),
        "make_phony": deps_value["make_phony"],
        "phony_targets": json_array_as_sorted_filenames(&deps_value, "phony_targets"),
    });

    let labels_ref_path = reference_dir.join("cli_json_outputs.labels.json");
    let deps_ref_path = reference_dir.join("cli_json_outputs.dependencies.json");

    if update_reference {
        let labels_text =
            serde_json::to_string_pretty(&labels_value).expect("serialize labels reference") + "\n";
        fs::write(&labels_ref_path, labels_text).unwrap_or_else(|err| {
            panic!(
                "Failed to write labels reference {}: {err}",
                labels_ref_path.display()
            )
        });

        let deps_text = serde_json::to_string_pretty(&normalized_deps)
            .expect("serialize dependencies reference")
            + "\n";
        fs::write(&deps_ref_path, deps_text).unwrap_or_else(|err| {
            panic!(
                "Failed to write dependencies reference {}: {err}",
                deps_ref_path.display()
            )
        });
        return;
    }

    let expected_labels: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&labels_ref_path).unwrap_or_else(|err| {
            panic!(
                "Missing labels reference {}: {err}",
                labels_ref_path.display()
            )
        }))
        .unwrap_or_else(|err| {
            panic!(
                "Invalid labels reference JSON {}: {err}",
                labels_ref_path.display()
            )
        });
    assert_eq!(
        labels_value, expected_labels,
        "labels JSON reference mismatch"
    );

    let expected_deps: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&deps_ref_path).unwrap_or_else(|err| {
            panic!(
                "Missing dependencies reference {}: {err}",
                deps_ref_path.display()
            )
        }))
        .unwrap_or_else(|err| {
            panic!(
                "Invalid dependencies reference JSON {}: {err}",
                deps_ref_path.display()
            )
        });
    assert_eq!(
        normalized_deps, expected_deps,
        "dependencies JSON reference mismatch"
    );
}

#[test]
fn default_native_diagnostic_codes_are_declared_in_vm_catalog() {
    let package = build_hierarchy_package_from_registry(&default_registry())
        .expect("runtime package build should succeed");
    let model = HierarchyExecutionModel::from_package_bytes(package.as_slice())
        .expect("runtime model load should succeed");

    let kinds = [
        AsmErrorKind::Assembler,
        AsmErrorKind::Cli,
        AsmErrorKind::Conditional,
        AsmErrorKind::Directive,
        AsmErrorKind::Expression,
        AsmErrorKind::Instruction,
        AsmErrorKind::Io,
        AsmErrorKind::Parser,
        AsmErrorKind::Preprocess,
        AsmErrorKind::Symbol,
    ];

    for kind in kinds {
        let diag = Diagnostic::new(1, Severity::Error, AsmError::new(kind, "probe", None));
        assert!(
            model.has_declared_diagnostic_code(diag.code()),
            "diagnostic code '{}' for {:?} should be declared in DIAG catalog",
            diag.code(),
            kind
        );
    }
}

fn assert_vm_native_diagnostic_core_parity(native_diag: &Diagnostic, runtime_diag: &Diagnostic) {
    assert_eq!(
        native_diag.code(),
        runtime_diag.code(),
        "code parity mismatch"
    );
    assert_eq!(
        native_diag.notes(),
        runtime_diag.notes(),
        "notes parity mismatch"
    );
    assert_eq!(
        native_diag.related_spans().len(),
        runtime_diag.related_spans().len(),
        "related span count parity mismatch"
    );
    assert_eq!(
        native_diag.severity(),
        runtime_diag.severity(),
        "severity parity mismatch"
    );
    assert_eq!(
        native_diag.line(),
        runtime_diag.line(),
        "line parity mismatch"
    );
    assert_eq!(
        native_diag.column(),
        runtime_diag.column(),
        "column-start parity mismatch"
    );
    assert_eq!(
        native_diag.col_end(),
        runtime_diag.col_end(),
        "column-end parity mismatch"
    );
}

fn assert_vm_native_first_fixit_parity(native_diag: &Diagnostic, runtime_diag: &Diagnostic) {
    assert_eq!(
        native_diag.fixits().len(),
        runtime_diag.fixits().len(),
        "fixit count parity mismatch"
    );
    assert!(
        !native_diag.fixits().is_empty(),
        "expected at least one native fixit"
    );
    assert!(
        !runtime_diag.fixits().is_empty(),
        "expected at least one runtime fixit"
    );

    let native_fixit = &native_diag.fixits()[0];
    let runtime_fixit = &runtime_diag.fixits()[0];
    assert_eq!(
        native_fixit.replacement, runtime_fixit.replacement,
        "fixit replacement parity mismatch"
    );
    assert_eq!(
        native_fixit.applicability, runtime_fixit.applicability,
        "fixit applicability parity mismatch"
    );
    assert_eq!(
        native_fixit.line, runtime_fixit.line,
        "fixit line parity mismatch"
    );
    assert_eq!(
        native_fixit.col_start, runtime_fixit.col_start,
        "fixit column start parity mismatch"
    );
    assert_eq!(
        native_fixit.col_end, runtime_fixit.col_end,
        "fixit column end parity mismatch"
    );
}

fn assert_vm_native_help_parity(native_diag: &Diagnostic, runtime_diag: &Diagnostic) {
    assert_eq!(
        native_diag.help().len(),
        runtime_diag.help().len(),
        "help count parity mismatch"
    );
    assert_eq!(
        native_diag.help(),
        runtime_diag.help(),
        "help text parity mismatch"
    );
}

#[test]
fn vm_native_diagnostic_parity_for_parser_error_code_severity_span() {
    let line = "MVI A,";
    let native = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, false);
    let runtime = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, true);

    assert_eq!(native.0, runtime.0, "status parity mismatch");
    let native_diag = native.1.expect("native diagnostic expected");
    let runtime_diag = runtime.1.expect("runtime diagnostic expected");

    assert_vm_native_diagnostic_core_parity(&native_diag, &runtime_diag);
}

#[test]
fn vm_native_diagnostic_parity_for_instruction_error_code_severity_span() {
    let line = "MVI A, 300";
    let native = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, false);
    let runtime = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, true);

    assert_eq!(native.0, runtime.0, "status parity mismatch");
    let native_diag = native.1.expect("native diagnostic expected");
    let runtime_diag = runtime.1.expect("runtime diagnostic expected");

    assert_vm_native_diagnostic_core_parity(&native_diag, &runtime_diag);
}

#[test]
fn intel8085_unknown_z80_mnemonic_emits_dialect_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, "LD A,B", true);
    assert_eq!(
        status,
        LineStatus::Error,
        "expected instruction error for 8085 LD syntax"
    );

    let diag = diag.expect("diagnostic expected");
    assert!(!diag.message().is_empty());

    let fixits = diag.fixits();
    assert_eq!(fixits.len(), 1, "expected one dialect suggestion fixit");
    let fixit = &fixits[0];
    assert_eq!(fixit.replacement, "MOV");
    assert_eq!(fixit.applicability, "maybe-incorrect");
    assert_eq!(fixit.line, 1);
    assert!(
        !diag.help().is_empty() && diag.help()[0].contains("Z80 dialect"),
        "expected dialect help hint"
    );
}

#[test]
fn vm_native_parity_for_dialect_fixit_payload() {
    let line = "LD A,B";
    let native = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, false);
    let runtime = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, true);

    assert_eq!(native.0, runtime.0, "status parity mismatch");
    let native_diag = native.1.expect("native diagnostic expected");
    let runtime_diag = runtime.1.expect("runtime diagnostic expected");

    assert_vm_native_diagnostic_core_parity(&native_diag, &runtime_diag);
    assert_vm_native_first_fixit_parity(&native_diag, &runtime_diag);
}

#[test]
fn intel8085_parser_error_with_z80_mnemonic_emits_dialect_fixit_hint() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, "LD A,", true);
    assert_eq!(status, LineStatus::Error, "expected parser error");

    let diag = diag.expect("diagnostic expected");
    assert!(!diag.help().is_empty(), "expected dialect help hint");
    assert!(
        diag.help()[0].contains("Z80 dialect"),
        "expected Z80 dialect wording in help hint"
    );
    assert_eq!(diag.fixits().len(), 1, "expected one parser-hint fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, "MOV");
    assert_eq!(fixit.applicability, "maybe-incorrect");
    assert_eq!(fixit.line, 1);
}

#[test]
fn vm_native_parity_for_parser_error_dialect_fixit_payload() {
    let line = "LD A,";
    let native = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, false);
    let runtime = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, true);

    assert_eq!(native.0, runtime.0, "status parity mismatch");
    let native_diag = native.1.expect("native diagnostic expected");
    let runtime_diag = runtime.1.expect("runtime diagnostic expected");

    assert_vm_native_diagnostic_core_parity(&native_diag, &runtime_diag);
    assert_eq!(
        native_diag.help().len(),
        runtime_diag.help().len(),
        "help count parity mismatch"
    );
    assert_vm_native_first_fixit_parity(&native_diag, &runtime_diag);
}

#[test]
fn unknown_directive_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".edif", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .EDIF"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endmod_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endmod", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDMOD"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDMODULE");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endsect_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endsect", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDSECT"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDSECTION");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endsec_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endsec", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDSEC"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDSECTION");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endmach_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endmach", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDMACH"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDMATCH");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_esleif_typo_emits_machine_applicable_fixit() {
    let (status, diag) =
        assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".esleif 1", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ESLEIF"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ELSEIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_elsif_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".elsif 1", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ELSIF"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ELSEIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_elif_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".elif 1", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ELIF"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ELSEIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_elsfi_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".elsfi 1", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ELSFI"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ELSEIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endmodle_typo_emits_machine_applicable_fixit() {
    let (status, diag) =
        assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endmodle", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDMODLE"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDMODULE");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_enidf_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".enidf", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENIDF"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_elsefi_typo_emits_machine_applicable_fixit() {
    let (status, diag) =
        assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".elsefi 1", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ELSEFI"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ELSEIF");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endmoduel_typo_emits_machine_applicable_fixit() {
    let (status, diag) =
        assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endmoduel", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDMODUEL"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDMODULE");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endsectio_typo_emits_machine_applicable_fixit() {
    let (status, diag) =
        assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endsectio", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDSECTIO"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDSECTION");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn unknown_directive_endmatc_typo_emits_machine_applicable_fixit() {
    let (status, diag) = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, ".endmatc", true);
    assert_eq!(status, LineStatus::Error, "expected directive error");

    let diag = diag.expect("diagnostic expected");
    assert!(diag.message().contains("Unknown directive .ENDMATC"));
    assert_eq!(diag.fixits().len(), 1, "expected one typo fixit");

    let fixit = &diag.fixits()[0];
    assert_eq!(fixit.replacement, ".ENDMATCH");
    assert_eq!(fixit.applicability, "machine-applicable");
    assert_eq!(fixit.line, 1);
}

#[test]
fn vm_native_parity_for_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".edif");
}

fn assert_directive_typo_vm_native_parity(line: &str) {
    let native = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, false);
    let runtime = assemble_line_diagnostic_with_runtime_mode(i8085_cpu_id, line, true);

    assert_eq!(native.0, runtime.0, "status parity mismatch");
    let native_diag = native.1.expect("native diagnostic expected");
    let runtime_diag = runtime.1.expect("runtime diagnostic expected");

    assert_vm_native_diagnostic_core_parity(&native_diag, &runtime_diag);
    assert_vm_native_help_parity(&native_diag, &runtime_diag);
    assert_vm_native_first_fixit_parity(&native_diag, &runtime_diag);
}

#[test]
fn vm_native_parity_for_endmod_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endmod");
}

#[test]
fn vm_native_parity_for_endsect_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endsect");
}

#[test]
fn vm_native_parity_for_endsec_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endsec");
}

#[test]
fn vm_native_parity_for_endmach_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endmach");
}

#[test]
fn vm_native_parity_for_esleif_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".esleif 1");
}

#[test]
fn vm_native_parity_for_elsif_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".elsif 1");
}

#[test]
fn vm_native_parity_for_elif_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".elif 1");
}

#[test]
fn vm_native_parity_for_elsfi_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".elsfi 1");
}

#[test]
fn vm_native_parity_for_endmodle_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endmodle");
}

#[test]
fn vm_native_parity_for_enidf_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".enidf");
}

#[test]
fn vm_native_parity_for_elsefi_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".elsefi 1");
}

#[test]
fn vm_native_parity_for_endmoduel_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endmoduel");
}

#[test]
fn vm_native_parity_for_endsectio_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endsectio");
}

#[test]
fn vm_native_parity_for_endmatc_directive_typo_fixit_payload() {
    assert_directive_typo_vm_native_parity(".endmatc");
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
        "errors" => Some("Assembly failed: ope005: invalid number: 5X5"),
        "statement_signature_error" => Some("Preprocess failed: Missing closing }]"),
        "statement_unquoted_comma_error" => {
            Some("Preprocess failed: Commas must be quoted in statement signatures")
        }
        "module_use_private_error" => Some("Assembly failed: Symbol is private: SECRET"),
        "linker_regions_phase6_contiguous_gap" => Some(
            "Assembly failed: contiguous output requires adjacent sections; gap $1001..$1001: b",
        ),
        "linker_regions_phase6_region_overlap" => Some(
            "Assembly failed: Region range overlaps existing region 'low' at $10F0..$10FF: high",
        ),
        "linker_regions_phase6_region_binding_conflict" => Some(
            "Assembly failed: Section is bound to region 'ram' but was placed in region 'rom': code",
        ),
        "linker_regions_phase6_emit_overflow" => Some(
            "Assembly failed: Value $100 (256) does not fit in 1-byte unit (max $FF)",
        ),
        "linker_regions_phase6_fill_in_bss_error" => {
            Some("Assembly failed: .fill is not allowed in kind=bss section (current kind=bss)")
        }
        _ => None,
    }
}

fn is_explicit_error_example_name(base: &str) -> bool {
    const ERROR_NAME_MARKERS: &[&str] = &[
        "error", "invalid", "overflow", "unknown", "conflict", "missing", "overlap", "gap", "fail",
    ];
    ERROR_NAME_MARKERS
        .iter()
        .any(|marker| base.contains(marker))
}

fn read_example_error_reference(reference_dir: &Path, base: &str) -> Option<String> {
    let path = reference_dir.join(format!("{base}.err"));
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end_matches(['\n', '\r']).to_string())
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
        let ref_err_path = reference_dir.join(format!("{base}.err"));

        let expected_error = read_example_error_reference(&reference_dir, base)
            .or_else(|| expected_example_error(base).map(|value| value.to_string()));
        if let Some(expected) = expected_error {
            assert!(
                is_explicit_error_example_name(base),
                "Error reference exists for non-explicit example name '{base}'. Rename the example to include an error marker (e.g. '*_error')."
            );
            if let Some(err) = assemble_example_error(&asm_path) {
                if update_reference {
                    fs::write(&ref_err_path, format!("{err}\n")).unwrap_or_else(|write_err| {
                        panic!(
                            "Failed to write reference error {}: {write_err}",
                            ref_err_path.display()
                        )
                    });
                } else {
                    assert_eq!(err, expected, "Unexpected error for {base}");
                }
                continue;
            }
            if !update_reference {
                panic!("Expected {base} to fail but it succeeded");
            }
            if ref_err_path.exists() {
                fs::remove_file(&ref_err_path).unwrap_or_else(|err| {
                    panic!(
                        "Failed to remove stale reference error {}: {err}",
                        ref_err_path.display()
                    )
                });
            }
        }

        if update_reference {
            let map_outputs = match assemble_example(&asm_path, &out_dir) {
                Ok(outputs) => outputs,
                Err(err) => panic!("Failed to assemble {base}: {err}"),
            };

            let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
                .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
            let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
                .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
            let ref_hex_path = reference_dir.join(format!("{base}.hex"));
            let ref_lst_path = reference_dir.join(format!("{base}.lst"));
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
            for (map_name, out_map) in &map_outputs {
                let ref_map_path = reference_dir.join(map_name);
                fs::write(&ref_map_path, out_map).unwrap_or_else(|err| {
                    panic!(
                        "Failed to write reference map {}: {err}",
                        ref_map_path.display()
                    )
                });
            }
            if ref_err_path.exists() {
                fs::remove_file(&ref_err_path).unwrap_or_else(|err| {
                    panic!(
                        "Failed to remove stale reference error {}: {err}",
                        ref_err_path.display()
                    )
                });
            }
            continue;
        }

        let map_outputs = match assemble_example(&asm_path, &out_dir) {
            Ok(outputs) => outputs,
            Err(err) => panic!("Failed to assemble {base}: {err}"),
        };

        let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
            .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
        let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
            .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
        let ref_hex_path = reference_dir.join(format!("{base}.hex"));
        let ref_lst_path = reference_dir.join(format!("{base}.lst"));
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
        for (map_name, out_map) in &map_outputs {
            let ref_map_path = reference_dir.join(map_name);
            let ref_map = fs::read(&ref_map_path).unwrap_or_else(|err| {
                panic!("Missing reference map {}: {err}", ref_map_path.display())
            });
            let out_map_text = String::from_utf8_lossy(out_map);
            let ref_map_text = String::from_utf8_lossy(&ref_map);
            if out_map_text != ref_map_text {
                let diff = diff_text(&ref_map_text, &out_map_text, 20);
                panic!("Map mismatch for {base} ({map_name})\n{diff}");
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
    let map_outputs = assemble_example_with_base(&asm_path, &out_dir, base)
        .unwrap_or_else(|err| panic!("Failed to assemble project_root example: {err}"));
    assert!(
        map_outputs.is_empty(),
        "project_root example unexpectedly generated map outputs"
    );

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
fn z80_cb_bit_set_res_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    BIT 3,B");
    assert_eq!(bytes, vec![0xCB, 0x58]);

    let bytes = assemble_bytes(z80_cpu_id, "    SET 5,(HL)");
    assert_eq!(bytes, vec![0xCB, 0xEE]);

    let bytes = assemble_bytes(z80_cpu_id, "    RES 1,A");
    assert_eq!(bytes, vec![0xCB, 0x8F]);
}

#[test]
fn z80_cb_rotate_shift_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    RLC C");
    assert_eq!(bytes, vec![0xCB, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    RLC (HL)");
    assert_eq!(bytes, vec![0xCB, 0x06]);

    let bytes = assemble_bytes(z80_cpu_id, "    RRC (HL)");
    assert_eq!(bytes, vec![0xCB, 0x0E]);

    let bytes = assemble_bytes(z80_cpu_id, "    SRA (HL)");
    assert_eq!(bytes, vec![0xCB, 0x2E]);
}

#[test]
fn z80_cb_indexed_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    BIT 2,(IX+5)");
    assert_eq!(bytes, vec![0xDD, 0xCB, 0x05, 0x56]);

    let bytes = assemble_bytes(z80_cpu_id, "    SET 7,(IY-2)");
    assert_eq!(bytes, vec![0xFD, 0xCB, 0xFE, 0xFE]);

    let bytes = assemble_bytes(z80_cpu_id, "    SRL (IX+0)");
    assert_eq!(bytes, vec![0xDD, 0xCB, 0x00, 0x3E]);
}

#[test]
fn m65c02_bbr_bbs_encode() {
    let bytes = assemble_bytes(m65c02_cpu_id, "    BBR0 $12,$0005");
    assert_eq!(bytes, vec![0x0F, 0x12, 0x02]);

    let bytes = assemble_bytes(m65c02_cpu_id, "    BBS7 $FE,$0000");
    assert_eq!(bytes, vec![0xFF, 0xFE, 0xFD]);
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
fn org_rejects_wide_addresses_on_legacy_cpu() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .org $123456", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn org_supports_wide_addresses_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .org $123456", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    assert_eq!(asm.start_addr(), 0x123456);
    assert_eq!(asm.aux_value(), 0x123456);
}

#[test]
fn org_rejects_address_above_24bit_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .org $01000000", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("exceeds max $FFFFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn region_rejects_wide_addresses_on_legacy_cpu() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .region hi, $120000, $1200ff", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn region_rejects_address_above_24bit_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .region hi, $01000000, $010000ff", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("exceeds max $FFFFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn place_allows_regions_above_64k_on_65816() {
    let lines = vec![
        ".module main".to_string(),
        ".cpu 65816".to_string(),
        ".region hi, $120000, $1200ff".to_string(),
        ".section code".to_string(),
        ".byte $aa, $bb".to_string(),
        ".endsection".to_string(),
        ".place code in hi".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0);

    let entries = assembler.image().entries().expect("entries");
    assert_eq!(entries, vec![(0x120000, 0xaa), (0x120001, 0xbb)]);
}

#[test]
fn place_rejects_wide_region_after_switching_back_to_legacy_cpu() {
    let lines = vec![
        ".module main".to_string(),
        ".cpu 65816".to_string(),
        ".region hi, $120000, $1200ff".to_string(),
        ".section code".to_string(),
        ".byte $aa".to_string(),
        ".endsection".to_string(),
        ".cpu 6502".to_string(),
        ".place code in hi".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains(".place/.pack address $120000 exceeds max $FFFF")
    }));
}

#[test]
fn align_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .align $20000", 1, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains(".align span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn align_supports_wide_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .align $20000", 1, 1);
    assert_eq!(status, LineStatus::DirDs);
    assert_eq!(asm.aux_value(), 0x1FFFF);
}

#[test]
fn align_rejects_non_power_of_two_boundary() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .align 3", 0x1000, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("power of two"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn ds_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .ds 2", 0xFFFF, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains(".ds span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn ds_supports_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .ds 2", 0xFFFF, 1);
    assert_eq!(status, LineStatus::DirDs);
    assert_eq!(asm.aux_value(), 2);
}

#[test]
fn ds_rejects_negative_count_without_wrap() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .ds -1", 0x1000, 1);
    assert_eq!(status, LineStatus::Error);
    let error = asm.error().unwrap();
    assert!(
        error.message().contains("non-negative") || error.message().contains("exceeds max"),
        "unexpected message: {}",
        error.message()
    );
}

#[test]
fn place_sets_section_base_for_image_emission() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section code".to_string(),
        ".byte 1, 2".to_string(),
        ".endsection".to_string(),
        ".place code in ram".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0);

    let mut bin = Vec::new();
    assembler
        .image()
        .write_bin_file(&mut bin, 0x1000, 0x1001, 0xff)
        .expect("bin");
    assert_eq!(bin, vec![1, 2]);
}

#[test]
fn pack_places_sections_in_order_and_alignment() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $2000, $20ff, align=1".to_string(),
        ".section a, align=1".to_string(),
        ".byte $aa".to_string(),
        ".endsection".to_string(),
        ".section b, align=2".to_string(),
        ".byte $bb".to_string(),
        ".endsection".to_string(),
        ".pack in ram : a, b".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0);

    let mut bin = Vec::new();
    assembler
        .image()
        .write_bin_file(&mut bin, 0x2000, 0x2002, 0xff)
        .expect("bin");
    assert_eq!(bin, vec![0xaa, 0xff, 0xbb]);
}

#[test]
fn wide_alignment_options_accept_32bit_values() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".region ram, $010001, $02ffff, align=$20000",
        ".section code, align=$10000",
        "start:",
        "    .byte $aa",
        ".endsection",
        ".place code in ram, align=$8000",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(entries, vec![(0x020000, 0xaa)]);
    assert_eq!(assembler.symbols().lookup("main.start"), Some(0x020000));
}

#[test]
fn section_symbols_are_finalized_from_layout_before_pass2() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $2000, $20ff".to_string(),
        ".section code".to_string(),
        "start: .word start".to_string(),
        ".endsection".to_string(),
        ".place code in ram".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0);

    let mut bin = Vec::new();
    assembler
        .image()
        .write_bin_file(&mut bin, 0x2000, 0x2001, 0xff)
        .expect("bin");
    assert_eq!(bin, vec![0x00, 0x20]);
}

#[test]
fn section_symbol_finalize_reports_address_overflow() {
    let mut symbols = SymbolTable::new();
    assert_eq!(
        symbols.add(
            "main.start",
            u32::MAX,
            false,
            SymbolVisibility::Private,
            None
        ),
        SymbolTableResult::Ok
    );
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    asm.layout.sections.insert(
        "code".to_string(),
        SectionState {
            base_addr: Some(1),
            ..SectionState::default()
        },
    );
    asm.layout
        .section_symbol_sections
        .insert("main.start".to_string(), "code".to_string());

    let errors = asm.finalize_section_symbol_addresses();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind(), AsmErrorKind::Directive);
    assert!(
        errors[0]
            .message()
            .contains("overflows address arithmetic for CPU"),
        "unexpected message: {}",
        errors[0].message()
    );
    assert!(errors[0].message().contains("main.start"));

    let entry = asm.symbols.entry("main.start").expect("symbol exists");
    assert_eq!(entry.val, u32::MAX);
    assert!(!entry.updated);
}

#[test]
fn section_size_uses_max_pc_with_forward_org_and_align() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $1003".to_string(),
        ".section code".to_string(),
        ".byte $aa".to_string(),
        ".align 4".to_string(),
        ".org 7".to_string(),
        ".org 2".to_string(),
        ".endsection".to_string(),
        ".place code in ram".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Section placement overflows region")
    }));
}

#[test]
fn pass1_errors_when_section_overflows_region() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $0800, $0802".to_string(),
        ".section code".to_string(),
        ".byte 1, 2, 3, 4".to_string(),
        ".endsection".to_string(),
        ".place code in ram".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Section placement overflows region")
    }));
}

#[test]
fn place_reports_address_range_overflow_in_arithmetic() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    asm.cpu_mode.program_address_max = u32::MAX;
    asm.layout.regions.insert(
        "ram".to_string(),
        RegionState {
            name: "ram".to_string(),
            start: u32::MAX - 1,
            end: u32::MAX,
            cursor: u32::MAX - 1,
            align: 1,
            placed: Vec::new(),
        },
    );
    asm.layout.sections.insert(
        "code".to_string(),
        SectionState {
            max_pc: 3,
            ..SectionState::default()
        },
    );
    let status = process_line(&mut asm, ".place code in ram", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("overflows address range"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn pass1_errors_when_regions_overlap() {
    let lines = vec![
        ".module main".to_string(),
        ".region low, $1000, $10ff".to_string(),
        ".region high, $10f0, $11ff".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Region range overlaps existing region")
    }));
}

#[test]
fn pass1_errors_when_region_bound_section_is_placed_in_other_region() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".region rom, $8000, $80ff".to_string(),
        ".section code, region=ram".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".place code in rom".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Section is bound to region 'ram' but was placed in region 'rom'")
    }));
}

#[test]
fn pass1_errors_for_unknown_section_in_deferred_place() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $0800, $08ff".to_string(),
        ".place missing in ram".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Unknown section in placement directive")
    }));
}

#[test]
fn pass1_errors_for_unknown_region_in_deferred_place() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $0800, $08ff".to_string(),
        ".section code".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".place code in nowhere".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Unknown region in placement directive")
    }));
}

#[test]
fn pass1_errors_when_region_bound_section_is_not_placed() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $0800, $08ff".to_string(),
        ".section code, region=ram".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler
        .diagnostics
        .iter()
        .any(|diag| { diag.error.message().contains("must be explicitly placed") }));
}

#[test]
fn pass1_errors_when_output_section_is_not_placed() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section code".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".output \"build/game.bin\", format=bin, sections=code".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error
            .message()
            .contains("Section referenced by .output must be explicitly placed")
    }));
}

#[test]
fn pass1_allows_output_section_when_placed() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section code".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".place code in ram".to_string(),
        ".output \"build/game.bin\", format=bin, sections=code".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);
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
fn byte_strings_use_active_encoding() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .byte \"Az\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x41, 0x7A]);

    let status = process_line(&mut asm, "    .enc petscii", 0, 2);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "    .byte \"Az\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xC1, 0x5A]);
}

#[test]
fn encoding_directive_accepts_known_names() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let status = process_line(&mut asm, "    .enc petscii", 0, 2);
    assert_eq!(status, LineStatus::Ok, "{}", asm.error_message());
    let status = process_line(&mut asm, "    .text \"a\"", 0, 2);
    assert_eq!(status, LineStatus::Ok, "{}", asm.error_message());
    assert_eq!(asm.bytes(), &[0x41]);

    let status = process_line(&mut asm, "    .enc ascii", 0, 2);
    assert_eq!(status, LineStatus::Ok, "{}", asm.error_message());
    let status = process_line(&mut asm, "    .text \"a\"", 0, 2);
    assert_eq!(status, LineStatus::Ok, "{}", asm.error_message());
    assert_eq!(asm.bytes(), &[0x61]);
}

#[test]
fn encoding_directive_rejects_unknown_encoding() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .enc unknown", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("Unknown encoding"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("ascii"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("petscii"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn text_directives_emit_encoded_bytes() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .enc petscii", 0, 2);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "    .text \"Az\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xC1, 0x5A]);

    let status = process_line(&mut asm, "    .null \"OK\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xCF, 0xCB, 0x00]);

    let status = process_line(&mut asm, "    .ptext \"dog\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x03, 0x44, 0x4F, 0x47]);
}

#[test]
fn null_directive_is_strict_for_zero_byte_input() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .null \"\\0\"", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("zero byte"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn ptext_rejects_encoded_strings_over_255_bytes() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let long_text = "a".repeat(256);
    let line = format!("    .ptext \"{long_text}\"");
    let status = process_line(&mut asm, &line, 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("exceeds 255 bytes"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn string_expressions_are_supported_by_portable_vm() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let status = process_line(&mut asm, "    .enc petscii", 0, 1);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "VAL .const 'a'", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    assert_eq!(asm.symbols().lookup("VAL"), Some(0x41));
}

#[test]
fn module_entry_resets_text_encoding_to_default() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    assert_eq!(
        process_line(&mut asm, ".module first", 0, 1),
        LineStatus::Ok
    );
    assert_eq!(
        process_line(&mut asm, "    .enc petscii", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(
        process_line(&mut asm, "    .text \"a\"", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(asm.bytes(), &[0x41]);
    assert_eq!(process_line(&mut asm, ".endmodule", 0, 1), LineStatus::Ok);

    assert_eq!(
        process_line(&mut asm, ".module second", 0, 1),
        LineStatus::Ok
    );
    assert_eq!(
        process_line(&mut asm, "    .text \"a\"", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(asm.bytes(), &[0x61]);
    assert_eq!(process_line(&mut asm, ".endmodule", 0, 1), LineStatus::Ok);
}

#[test]
fn encode_definition_directives_build_custom_encoding() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .encode custom", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .cdef \"A\", \"Z\", 1", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .tdef \"xy\", 60", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .edef \"{cr}\", 13", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .endencode", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .enc custom", 0, 2);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "    .byte \"A{cr}xy\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[1, 13, 60, 61]);
}

#[test]
fn encode_can_clone_from_base_encoding() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .encode clone, petscii", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .endencode", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .enc clone", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .byte \"Az\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xC1, 0x5A]);
}

#[test]
fn tdef_accepts_explicit_value_lists() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .encode custom", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .tdef \"ab\", 10, 20", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .endencode", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .enc custom", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .byte \"ab\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[10, 20]);
}

#[test]
fn cdef_requires_encode_scope() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .cdef \"A\", \"Z\", 1", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("inside .encode"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn endencode_requires_matching_encode() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .endencode", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("without matching .encode"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn endmodule_rejects_open_encode_scope() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".module main", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .encode custom", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".endmodule", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("open .encode block"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn emit_supports_word_and_long_units() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .emit word, $1234", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x34, 0x12]);

    let status = process_line(&mut asm, "    .emit long, $11223344", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x44, 0x33, 0x22, 0x11]);
}

#[test]
fn emit_overflow_is_error() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .emit byte, 256", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().map(|e| e.kind()), Some(AsmErrorKind::Directive));
    assert!(
        asm.error_message().contains("does not fit in 1-byte unit"),
        "{}",
        asm.error_message()
    );
    assert!(
        asm.error_message().contains("$100"),
        "{}",
        asm.error_message()
    );
}

#[test]
fn emit_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .emit byte, 1, 2", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains(".emit span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn emit_supports_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .emit byte, 1, 2", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[1, 2]);
}

#[test]
fn fill_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .fill byte, 2, $ff", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains(".fill span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn fill_supports_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .fill byte, 2, $ff", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xFF, 0xFF]);
}

#[test]
fn fill_rejects_negative_count_without_wrap() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .fill byte, -1, $ff", 0x1000, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Expression);
    assert!(
        asm.error().unwrap().message().contains("non-negative"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn byte_list_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .byte 1, 2", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains(".byte span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn byte_list_supports_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .byte 1, 2", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[1, 2]);
}

#[test]
fn instruction_rejects_span_beyond_legacy_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    LDA #$01", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("instruction LDA span"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn instruction_supports_span_on_65816() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "    .cpu 65816", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    LDA #$01", 0xFFFF, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xA9, 0x01]);
}

#[test]
fn update_addresses_reports_section_address_arithmetic_overflow() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    asm.layout.current_section = Some("code".to_string());
    asm.layout.sections.insert(
        "code".to_string(),
        SectionState {
            start_pc: u32::MAX,
            pc: 1,
            ..SectionState::default()
        },
    );
    let mut addr = 0u32;
    let result = asm.update_addresses(&mut addr, LineStatus::Ok);
    assert!(result.is_err());
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("overflows address arithmetic"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn update_addresses_reports_main_pc_beyond_cpu_max() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    asm.bytes = vec![0xEA, 0xEA];
    let mut addr = 0xFFFF;
    let result = asm.update_addresses(&mut addr, LineStatus::Ok);
    assert!(result.is_err());
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error().unwrap().message().contains("exceeds max $FFFF"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn current_addr_reports_section_address_arithmetic_overflow() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    asm.layout.current_section = Some("code".to_string());
    asm.layout.sections.insert(
        "code".to_string(),
        SectionState {
            start_pc: u32::MAX,
            pc: 1,
            ..SectionState::default()
        },
    );
    let result = asm.current_addr(0);
    assert!(result.is_err());
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    assert!(
        asm.error()
            .unwrap()
            .message()
            .contains("overflows address arithmetic"),
        "unexpected message: {}",
        asm.error().unwrap().message()
    );
}

#[test]
fn res_allows_wide_total_and_reports_size() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".cpu 65816", 0, 1);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, ".section vars, kind=bss", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .res long, 20000", 0, 1);
    assert_eq!(status, LineStatus::DirDs);
    assert_eq!(asm.aux_value(), 80_000);
}

#[test]
fn res_rejects_span_beyond_legacy_max() {
    let lines = vec![
        ".module main".to_string(),
        ".section vars, kind=bss".to_string(),
        ".org $ffff".to_string(),
        ".res byte, 2".to_string(),
        ".endsection".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert!(pass1.errors > 0);
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error.message().contains(".res span")
            && diag.error.message().contains("exceeds max $FFFF")
    }));
}

#[test]
fn res_supports_span_on_65816() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".section vars, kind=bss",
        ".org $ffff",
        ".res byte, 2",
        ".endsection",
        ".endmodule",
    ]);

    assert_eq!(assembler.image().num_entries(), 0);
}

#[test]
fn res_requires_bss_section_kind() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".section vars, kind=data", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .res byte, 2", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("only allowed in kind=bss"));
    assert!(asm.error_message().contains("current kind=data"));
}

#[test]
fn bss_section_rejects_fill_and_byte() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".section vars, kind=bss", 0, 1);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "    .res byte, 3", 0, 1);
    assert_eq!(status, LineStatus::DirDs);
    assert_eq!(asm.aux_value(), 3);

    let status = process_line(&mut asm, "    .fill byte, 1, $ff", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("not allowed in kind=bss"));

    let status = process_line(&mut asm, "    .byte 1", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("not allowed in kind=bss"));
}

#[test]
fn section_option_requires_key_value_form() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".section code, align", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains("Expected section option in key=value form"));
}

#[test]
fn section_option_rejects_unknown_key() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".section code, bogus=1", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("Unknown section option key"));
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
fn const_supports_negative_values() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "NEG .const -1", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    assert_eq!(asm.symbols().lookup("NEG"), Some(u32::MAX));

    let status = process_line(&mut asm, "    .word NEG", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xFF, 0xFF]);
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
fn namespace_scopes_qualify_symbols() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".namespace outer", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".namespace inner", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "VAL .const 9", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    let status = process_line(&mut asm, ".endn", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".endnamespace", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .word outer.inner.VAL", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[9, 0]);
}

#[test]
fn namespace_shadowing_prefers_inner_scope() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "VAL .const 1", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    let status = process_line(&mut asm, ".namespace scope", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "VAL .const 2", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    let status = process_line(&mut asm, "    .word VAL", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[2, 0]);
    let status = process_line(&mut asm, ".endn", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .word VAL", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[1, 0]);
}

#[test]
fn bend_alias_closes_block_scope() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "SCOPE .block", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "VAL .const 3", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    let status = process_line(&mut asm, ".bend", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .word SCOPE.VAL", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[3, 0]);
}

#[test]
fn namespace_close_rejects_mismatched_scope_kind() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "SCOPE .block", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".endnamespace", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains(".endnamespace found but current scope was opened by .block"));
}

#[test]
fn block_close_rejects_mismatched_scope_kind() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".namespace scope", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".endblock", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains(".endblock found but current scope was opened by .namespace"));
}

#[test]
fn endn_without_namespace_errors() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".endn", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains(".endnamespace found without matching .namespace"));
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
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.fixits().iter().any(|fixit| {
            fixit.replacement == ".endmodule"
                && fixit
                    .applicability
                    .eq_ignore_ascii_case("machine-applicable")
        })
    }));
}

#[test]
fn dsection_directive_is_removed() {
    let assembler = run_pass1(&[".module main", ".dsection code", ".endmodule"]);
    assert!(assembler
        .diagnostics
        .iter()
        .any(|diag| diag.error.message().contains(".dsection has been removed")));
}

#[test]
fn placed_section_without_dsection_emits_hex() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section data".to_string(),
        ".byte 1, 2".to_string(),
        ".endsection".to_string(),
        ".place data in ram".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut output = Vec::new();
    {
        let mut listing = ListingWriter::new(&mut output, false);
        listing
            .header(&format!("opForge Assembler v{VERSION}"))
            .expect("listing header");
        let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
        listing
            .footer_with_generated_output(
                &pass2,
                assembler.symbols(),
                assembler.image().num_entries(),
                &assembler.image().entries().expect("generated output"),
            )
            .expect("listing footer");
    }
    let listing_text = String::from_utf8_lossy(&output);
    assert!(listing_text.contains("GENERATED OUTPUT"), "{listing_text}");
    assert!(listing_text.contains("1000    01 02"), "{listing_text}");

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
fn packed_sections_without_dsection_emit_hex() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section a".to_string(),
        ".byte $aa".to_string(),
        ".endsection".to_string(),
        ".section b".to_string(),
        ".byte $bb".to_string(),
        ".endsection".to_string(),
        ".pack in ram : a, b".to_string(),
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
        .header(&format!("opForge Assembler v{VERSION}"))
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
        hex_text.contains(":02100000AABB89"),
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
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.fixits().iter().any(|fixit| {
            fixit.replacement == ".endsection"
                && fixit
                    .applicability
                    .eq_ignore_ascii_case("machine-applicable")
        })
    }));
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
        .header(&format!("opForge Assembler v{VERSION}"))
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
fn empty_module_emits_only_hex_eof_record() {
    let lines = vec![".module main".to_string(), ".endmodule".to_string()];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&lines);
    assert_eq!(pass1.errors, 0);

    let mut output = Vec::new();
    let mut listing = ListingWriter::new(&mut output, false);
    listing
        .header(&format!("opForge Assembler v{VERSION}"))
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
    assert_eq!(hex_text.trim(), ":00000001FF");
}

#[test]
fn section_selects_and_restores_output_target() {
    let lines = vec![
        ".module main".to_string(),
        ".region ram, $1000, $10ff".to_string(),
        ".section data".to_string(),
        ".byte 1".to_string(),
        ".endsection".to_string(),
        ".byte 2".to_string(),
        ".place data in ram".to_string(),
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
        .header(&format!("opForge Assembler v{VERSION}"))
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
        hex_text.contains(":0100000002FD"),
        "unexpected hex output: {hex_text}"
    );
    assert!(
        hex_text.contains(":0110000001EE"),
        "unexpected hex output: {hex_text}"
    );
}

#[test]
fn rts_encodes_in_6502_family() {
    let lines = vec![
        ".module main".to_string(),
        ".cpu 6502".to_string(),
        ".org 1000h".to_string(),
        "    rts".to_string(),
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
        .header(&format!("opForge Assembler v{VERSION}"))
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
        hex_text.contains(":01100000608F"),
        "unexpected hex output: {hex_text}"
    );
}

#[test]
fn cpu_65816_aliases_are_accepted() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 65c816", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu w65c816", 0, 1), LineStatus::Ok);
}

#[test]
fn cpu_65816_can_assemble_family_instruction() {
    let bytes = assemble_bytes(m65816_cpu_id, "    RTS");
    assert_eq!(bytes, vec![0x60]);
}

#[test]
fn unknown_cpu_diagnostic_lists_65816_and_aliases() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".cpu nope816", 0, 1);
    assert_eq!(status, LineStatus::Error);

    let message = asm
        .error()
        .expect("expected unknown cpu error")
        .message()
        .to_string();
    assert!(message.contains("65816"), "unexpected message: {message}");
    assert!(message.contains("65c816"), "unexpected message: {message}");
    assert!(message.contains("w65c816"), "unexpected message: {message}");
}

#[test]
fn cpu_6809_and_hd6309_aliases_are_accepted() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu m6809", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 6809", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu mc6809", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu hd6309", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 6309", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu m6309", 0, 1), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu h6309", 0, 1), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".cpu hitachi6309", 0, 1),
        LineStatus::Ok
    );
}

#[test]
fn m6809_can_assemble_basic_instructions() {
    assert_eq!(assemble_bytes(m6809_cpu_id, "    NOP"), vec![0x12]);
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA #$2A"),
        vec![0x86, 0x2A]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDD #$1234"),
        vec![0xCC, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDX #$4567"),
        vec![0x8E, 0x45, 0x67]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDY #$4567"),
        vec![0x10, 0x8E, 0x45, 0x67]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDU #$89AB"),
        vec![0xCE, 0x89, 0xAB]
    );
}

#[test]
fn m6809_indexed_and_register_list_modes_encode() {
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA $20,X"),
        vec![0xA6, 0x88, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA A,X"),
        vec![0xA6, 0x86]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    PSHS A,B,CC"),
        vec![0x34, 0x07]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    PSHU A,B,S"),
        vec![0x36, 0x46]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    BCC $0012"),
        vec![0x24, 0x10]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    BLO $0012"),
        vec![0x25, 0x10]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STA $20,X"),
        vec![0xA7, 0x88, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STB A,X"),
        vec![0xE7, 0x86]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STY $20,X"),
        vec![0x10, 0xAF, 0x88, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    JSR $20,X"),
        vec![0xAD, 0x88, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    JMP A,X"),
        vec![0x6E, 0x86]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA [$20,X]"),
        vec![0xA6, 0x98, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA [A,X]"),
        vec![0xA6, 0x96]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA [$1234]"),
        vec![0xA6, 0x9F, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA [4,PC]"),
        vec![0xA6, 0x9C, 0x04]
    );
    assert_eq!(assemble_bytes(m6809_cpu_id, "    LDA ,X"), vec![0xA6, 0x00]);
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA ,X+"),
        vec![0xA6, 0x80]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA ,X++"),
        vec![0xA6, 0x81]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA ,-X"),
        vec![0xA6, 0x82]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDA ,--S"),
        vec![0xA6, 0xE3]
    );
}

#[test]
fn m6809_extended_and_direct_modes_encode() {
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STA $1234"),
        vec![0xB7, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STX $20"),
        vec![0x9F, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDY $20"),
        vec![0x10, 0x9E, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    LDY $1234"),
        vec![0x10, 0xBE, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STY $20"),
        vec![0x10, 0x9F, 0x20]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STY $1234"),
        vec![0x10, 0xBF, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    STU $1234"),
        vec![0xFF, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    JSR $1234"),
        vec![0xBD, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    JMP $1234"),
        vec![0x7E, 0x12, 0x34]
    );
}

#[test]
fn m6809_reports_register_list_validation_errors() {
    let (status, message) = assemble_line_status(m6809_cpu_id, "    PSHS $20");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.to_ascii_uppercase().contains("REGISTER-LIST"),
        "unexpected error message: {message}"
    );

    let (status, message) = assemble_line_status(m6809_cpu_id, "    PSHS S");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.to_ascii_uppercase().contains("INVALID REGISTER S"),
        "unexpected error message: {message}"
    );
}

#[test]
fn m6809_reports_indexed_auto_inc_dec_validation_errors() {
    let (status, message) = assemble_line_status(m6809_cpu_id, "    LDA 1,X+");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message
            .to_ascii_uppercase()
            .contains("AUTO INC/DEC FORM DOES NOT ALLOW DISPLACEMENT"),
        "unexpected error message: {message}"
    );

    let (status, message) = assemble_line_status(m6809_cpu_id, "    LDA ,PC+");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message
            .to_ascii_uppercase()
            .contains("REQUIRES X/Y/U/S BASE REGISTER"),
        "unexpected error message: {message}"
    );
}

#[test]
fn m6809_reports_invalid_register_pairs_for_tfr_exg() {
    let (status, message) = assemble_line_status(m6809_cpu_id, "    TFR A,X");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message
            .to_ascii_uppercase()
            .contains("INVALID REGISTER PAIR A,X"),
        "unexpected error message: {message}"
    );

    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    TFR A,B"),
        vec![0x1F, 0x89]
    );
    assert_eq!(
        assemble_bytes(m6809_cpu_id, "    EXG X,Y"),
        vec![0x1E, 0x12]
    );
}

#[test]
fn m6809_branch_range_boundaries_are_validated() {
    {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);
        asm.clear_conditionals();
        asm.clear_scopes();
        assert_eq!(asm.process("    BRA $0081", 1, 0, 2), LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x20, 0x7F]);
    }

    {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);
        asm.clear_conditionals();
        asm.clear_scopes();
        assert_eq!(asm.process("    BRA $0082", 1, 0, 2), LineStatus::Error);
        let message = asm
            .error()
            .expect("branch out-of-range should produce an error")
            .message()
            .to_string();
        assert!(
            message.contains("Branch target out of range"),
            "unexpected message: {message}"
        );
    }

    {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);
        asm.clear_conditionals();
        asm.clear_scopes();
        assert_eq!(asm.process("    LBRA $8002", 1, 0, 2), LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x16, 0x7F, 0xFF]);
    }

    {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);
        asm.clear_conditionals();
        asm.clear_scopes();
        assert_eq!(asm.process("    LBRA $8003", 1, 0, 2), LineStatus::Error);
        let message = asm
            .error()
            .expect("long-branch out-of-range should produce an error")
            .message()
            .to_string();
        assert!(
            message.contains("Long branch target out of range"),
            "unexpected message: {message}"
        );
    }
}

#[test]
fn hd6309_supports_extension_instruction() {
    assert_eq!(assemble_bytes(hd6309_cpu_id, "    SEXW"), vec![0x14]);
    assert_eq!(assemble_bytes(hd6309_cpu_id, "    CLRD"), vec![0x10, 0x4F]);
    assert_eq!(assemble_bytes(hd6309_cpu_id, "    CLRW"), vec![0x10, 0x5F]);
    assert_eq!(assemble_bytes(hd6309_cpu_id, "    CLRE"), vec![0x11, 0x4F]);
    assert_eq!(assemble_bytes(hd6309_cpu_id, "    CLRF"), vec![0x11, 0x5F]);
}

#[test]
fn hd6309_supports_6809_prefixed_ldy_sty_instructions() {
    assert_eq!(
        assemble_bytes(hd6309_cpu_id, "    LDY #$1234"),
        vec![0x10, 0x8E, 0x12, 0x34]
    );
    assert_eq!(
        assemble_bytes(hd6309_cpu_id, "    STY $20"),
        vec![0x10, 0x9F, 0x20]
    );
    assert_eq!(
        assemble_bytes(hd6309_cpu_id, "    STY $20,X"),
        vec![0x10, 0xAF, 0x88, 0x20]
    );
}

#[test]
fn m6809_rejects_hd6309_extension_instruction() {
    let (status, message) = assemble_line_status(m6809_cpu_id, "    SEXW");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.to_ascii_uppercase().contains("SEXW"),
        "unexpected error message: {message}"
    );

    let (status, message) = assemble_line_status(m6809_cpu_id, "    CLRD");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.to_ascii_uppercase().contains("CLRD"),
        "unexpected error message: {message}"
    );
}

#[test]
fn unknown_cpu_diagnostic_lists_6809_and_hd6309_aliases() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".cpu nope6309", 0, 1);
    assert_eq!(status, LineStatus::Error);

    let message = asm
        .error()
        .expect("expected unknown cpu error")
        .message()
        .to_string();
    assert!(message.contains("m6809"), "unexpected message: {message}");
    assert!(message.contains("6809"), "unexpected message: {message}");
    assert!(message.contains("hd6309"), "unexpected message: {message}");
    assert!(message.contains("6309"), "unexpected message: {message}");
    assert!(message.contains("h6309"), "unexpected message: {message}");
    assert!(
        message.contains("hitachi6309"),
        "unexpected message: {message}"
    );
}

#[test]
fn m65816_prioritized_instruction_encoding() {
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    BRL $0005"),
        vec![0x82, 0x02, 0x00]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    JSL $123456"),
        vec![0x22, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    JMP [$1234]"),
        vec![0xDC, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    JML [$1234]"),
        vec![0xDC, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    MVN $01,$02"),
        vec![0x54, 0x01, 0x02]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    PEA $1234"),
        vec![0xF4, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    REP #$30"),
        vec![0xC2, 0x30]
    );
    assert_eq!(assemble_bytes(m65816_cpu_id, "    TXY"), vec![0x9B]);
    assert_eq!(assemble_bytes(m65816_cpu_id, "    TYX"), vec![0xBB]);
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    BRK #$12"),
        vec![0x00, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    JSR ($1234,X)"),
        vec![0xFC, 0x34, 0x12]
    );
}

#[test]
fn m65816_rep_sep_control_immediate_width_state() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        "    REP #$30",
        "    LDA #$1234",
        "    LDX #$5678",
        "    SEP #$20",
        "    LDA #$9A",
        "    SEP #$10",
        "    LDX #$BC",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x30),
            (0x0002, 0xA9),
            (0x0003, 0x34),
            (0x0004, 0x12),
            (0x0005, 0xA2),
            (0x0006, 0x78),
            (0x0007, 0x56),
            (0x0008, 0xE2),
            (0x0009, 0x20),
            (0x000A, 0xA9),
            (0x000B, 0x9A),
            (0x000C, 0xE2),
            (0x000D, 0x10),
            (0x000E, 0xA2),
            (0x000F, 0xBC),
        ]
    );
}

#[test]
fn m65816_cpu_switch_resets_width_state() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, "    REP #$30", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 6502", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    LDA #$1234", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error()
        .expect("expected immediate width error")
        .message()
        .contains("8-bit mode"));
}

#[test]
fn m65816_cpu_switch_resets_banked_assume_state() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$12, pbr=$34, dp=$2000",
        ".cpu 6502",
        ".cpu 65816",
        "    LDA $123456",
        "    LDA $20F0",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xAF),
            (0x0001, 0x56),
            (0x0002, 0x34),
            (0x0003, 0x12),
            (0x0004, 0xAD),
            (0x0005, 0xF0),
            (0x0006, 0x20),
        ]
    );
}

#[test]
fn m65816_cpu_switch_reset_restores_default_pbr() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$34", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(process_line(&mut asm, ".cpu 6502", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    JMP $343210", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$00"));
}

#[test]
fn m65816_assume_sets_runtime_state_and_immediate_widths() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(
            &mut asm,
            ".assume e=native, m=16, x=16, dbr=$12, pbr=$34, dp=$2000",
            0,
            2
        ),
        LineStatus::Ok
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::EMULATION_MODE_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::ACCUMULATOR_8BIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::INDEX_8BIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::DATA_BANK_KEY)
            .copied(),
        Some(0x12)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::DATA_BANK_EXPLICIT_KEY)
            .copied(),
        Some(1)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::PROGRAM_BANK_KEY)
            .copied(),
        Some(0x34)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::PROGRAM_BANK_EXPLICIT_KEY)
            .copied(),
        Some(1)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::DIRECT_PAGE_KEY)
            .copied(),
        Some(0x2000)
    );

    assert_eq!(
        process_line(&mut asm, "    LDA #$1234", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(asm.bytes().to_vec(), vec![0xA9, 0x34, 0x12]);
    assert_eq!(
        process_line(&mut asm, "    LDX #$5678", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(asm.bytes().to_vec(), vec![0xA2, 0x78, 0x56]);
}

#[test]
fn m65816_assume_emulation_forces_8bit_mode() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume e=native, m=16, x=16", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(
        process_line(&mut asm, ".assume e=emulation", 0, 2),
        LineStatus::Ok
    );

    let status = process_line(&mut asm, "    LDA #$1234", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error()
        .expect("expected immediate width error")
        .message()
        .contains("8-bit mode"));
}

#[test]
fn m65816_assume_rejects_invalid_values() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    let status = process_line(&mut asm, ".assume e=emulation, m=16", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains(".assume m=16 requires native mode"));

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    let status = process_line(&mut asm, ".assume dbr=256", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("out of range (0-255)"));
}

#[test]
fn m65816_assume_bank_auto_resets_explicit_flags() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume dbr=$12, pbr=$34", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(
        process_line(&mut asm, ".assume dbr=auto, pbr=auto", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::DATA_BANK_EXPLICIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_mode
            .state_flags
            .get(crate::m65816::state::PROGRAM_BANK_EXPLICIT_KEY)
            .copied(),
        Some(0)
    );
}

#[test]
fn m65816_phk_plb_invalidates_dbr_even_with_explicit_pbr() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12, dbr=$00",
        "    PHK",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x4B),
            (0x0001, 0xAB),
            (0x0002, 0xAF),
            (0x0003, 0x56),
            (0x0004, 0x34),
            (0x0005, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_does_not_infer_dbr_when_pbr_is_not_explicit() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $123400",
        ".assume pbr=auto, dbr=$00",
        "    PHK",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x123400, 0x4B),
            (0x123401, 0xAB),
            (0x123402, 0xAF),
            (0x123403, 0x56),
            (0x123404, 0x34),
            (0x123405, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_invalidates_dbr_even_when_pbr_changes_after_push() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12, dbr=$00",
        "    PHK",
        ".assume pbr=$34",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x4B),
            (0x0001, 0xAB),
            (0x0002, 0xAF),
            (0x0003, 0x56),
            (0x0004, 0x34),
            (0x0005, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_does_not_retroactively_use_later_pbr_explicitness() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $123400",
        ".assume pbr=auto, dbr=$00",
        "    PHK",
        ".assume pbr=$12",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x123400, 0x4B),
            (0x123401, 0xAB),
            (0x123402, 0xAF),
            (0x123403, 0x56),
            (0x123404, 0x34),
            (0x123405, 0x12),
        ]
    );
}

#[test]
fn m65816_phb_plb_invalidates_known_dbr_state() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$12",
        "    PHB",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x8B),
            (0x0001, 0xAB),
            (0x0002, 0xAF),
            (0x0003, 0x56),
            (0x0004, 0x34),
            (0x0005, 0x12),
        ]
    );
}

#[test]
fn m65816_phb_plb_keeps_dbr_unknown_when_auto() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $123400",
        ".assume dbr=auto",
        "    PHB",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x123400, 0x8B),
            (0x123401, 0xAB),
            (0x123402, 0xAF),
            (0x123403, 0x56),
            (0x123404, 0x34),
            (0x123405, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_invalidates_dbr_across_stack_neutral_instruction() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12, dbr=$00",
        "    PHK",
        "    NOP",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x4B),
            (0x0001, 0xEA),
            (0x0002, 0xAB),
            (0x0003, 0xAF),
            (0x0004, 0x56),
            (0x0005, 0x34),
            (0x0006, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_inference_is_cleared_by_stack_mutation() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12, dbr=$00",
        "    PHK",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x4B),
            (0x0001, 0x48),
            (0x0002, 0xAB),
            (0x0003, 0xAF),
            (0x0004, 0x56),
            (0x0005, 0x34),
            (0x0006, 0x12),
        ]
    );
}

#[test]
fn m65816_plb_unknown_source_prefers_long_when_available() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$12",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x48),
            (0x0001, 0xAB),
            (0x0002, 0xAF),
            (0x0003, 0x56),
            (0x0004, 0x34),
            (0x0005, 0x12),
        ]
    );
}

#[test]
fn m65816_plb_unknown_source_errors_for_non_long_mnemonics() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume dbr=$12", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(process_line(&mut asm, "    PHA", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, "    PLB", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    LDX $123456", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume dbr=... is unknown"));
    assert!(asm
        .error_message()
        .contains("update .assume near this site"));
}

#[test]
fn m65816_unknown_dbr_diagnostic_suggests_long_override_when_supported() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume dbr=$12", 0, 2),
        LineStatus::Ok
    );
    assert_eq!(process_line(&mut asm, "    PHA", 0, 2), LineStatus::Ok);
    assert_eq!(process_line(&mut asm, "    PLB", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    LDA $123456,b", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume dbr=... is unknown"));
    assert!(asm.error_message().contains("forced with ',l'"));
}

#[test]
fn m65816_lda_imm_pha_plb_does_not_infer_dbr() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDA #$12",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x48),
            (0x0003, 0xAB),
            (0x0004, 0xAF),
            (0x0005, 0x56),
            (0x0006, 0x34),
            (0x0007, 0x12),
        ]
    );
}

#[test]
fn m65816_lda_imm_pha_plb_is_conservative_with_intervening_ops() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDA #$12",
        "    ADC #$01",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x69),
            (0x0003, 0x01),
            (0x0004, 0x48),
            (0x0005, 0xAB),
            (0x0006, 0xAF),
            (0x0007, 0x56),
            (0x0008, 0x34),
            (0x0009, 0x12),
        ]
    );
}

#[test]
fn m65816_lda_imm_pha_plb_does_not_infer_dbr_across_flag_and_width_ops() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDA #$12",
        "    CLC",
        "    REP #$20",
        "    SEP #$20",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x18),
            (0x0003, 0xC2),
            (0x0004, 0x20),
            (0x0005, 0xE2),
            (0x0006, 0x20),
            (0x0007, 0x48),
            (0x0008, 0xAB),
            (0x0009, 0xAF),
            (0x000A, 0x56),
            (0x000B, 0x34),
            (0x000C, 0x12),
        ]
    );
}

#[test]
fn m65816_pea_plb_does_not_infer_dbr() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    PEA $3412",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xF4),
            (0x0001, 0x12),
            (0x0002, 0x34),
            (0x0003, 0xAB),
            (0x0004, 0xAF),
            (0x0005, 0x56),
            (0x0006, 0x34),
            (0x0007, 0x12),
        ]
    );
}

#[test]
fn m65816_pea_plb_inference_is_cleared_by_intervening_stack_mutation() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    PEA $3412",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xF4),
            (0x0001, 0x12),
            (0x0002, 0x34),
            (0x0003, 0x48),
            (0x0004, 0xAB),
            (0x0005, 0xAF),
            (0x0006, 0x56),
            (0x0007, 0x34),
            (0x0008, 0x12),
        ]
    );
}

#[test]
fn m65816_lda_imm_pha_plb_does_not_infer_dbr_across_a_preserving_stack_and_index_ops() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDA #$12",
        "    PHX",
        "    INX",
        "    PHA",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0xDA),
            (0x0003, 0xE8),
            (0x0004, 0x48),
            (0x0005, 0xAB),
            (0x0006, 0xAF),
            (0x0007, 0x56),
            (0x0008, 0x34),
            (0x0009, 0x12),
        ]
    );
}

#[test]
fn m65816_ldx_imm_phx_plb_does_not_infer_dbr() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDX #$12",
        "    PHX",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA2),
            (0x0001, 0x12),
            (0x0002, 0xDA),
            (0x0003, 0xAB),
            (0x0004, 0xAF),
            (0x0005, 0x56),
            (0x0006, 0x34),
            (0x0007, 0x12),
        ]
    );
}

#[test]
fn m65816_ldy_imm16_phy_plb_does_not_infer_dbr_from_low_byte() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    REP #$10",
        "    LDY #$3412",
        "    PHY",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x10),
            (0x0002, 0xA0),
            (0x0003, 0x12),
            (0x0004, 0x34),
            (0x0005, 0x5A),
            (0x0006, 0xAB),
            (0x0007, 0xAF),
            (0x0008, 0x56),
            (0x0009, 0x34),
            (0x000A, 0x12),
        ]
    );
}

#[test]
fn m65816_ldx_imm_phx_plb_inference_is_conservative_with_intervening_ops() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDX #$12",
        "    NOP",
        "    PHX",
        "    PLB",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA2),
            (0x0001, 0x12),
            (0x0002, 0xEA),
            (0x0003, 0xDA),
            (0x0004, 0xAB),
            (0x0005, 0xAF),
            (0x0006, 0x56),
            (0x0007, 0x34),
            (0x0008, 0x12),
        ]
    );
}

#[test]
fn m65816_phk_plb_inference_is_cleared_by_control_flow() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12, dbr=$00",
        "    PHK",
        "    BEQ after",
        "    PLB",
        "after:",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x4B),
            (0x0001, 0xF0),
            (0x0002, 0x01),
            (0x0003, 0xAB),
            (0x0004, 0xAF),
            (0x0005, 0x56),
            (0x0006, 0x34),
            (0x0007, 0x12),
        ]
    );
}

#[test]
fn m65816_assume_dbr_prefers_absolute_for_matching_24bit_bank() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$12",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x0000, 0xAD), (0x0001, 0x56), (0x0002, 0x34)]
    );

    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$00",
        "    LDA $123456",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xAF),
            (0x0001, 0x56),
            (0x0002, 0x34),
            (0x0003, 0x12)
        ]
    );
}

#[test]
fn m65816_assume_dbr_auto_uses_current_bank_for_resolution() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $123400",
        ".assume dbr=auto",
        "    LDA $123456",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x123400, 0xAD), (0x123401, 0x56), (0x123402, 0x34)]
    );
}

#[test]
fn m65816_assume_dbr_applies_to_non_long_mnemonics() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dbr=$12",
        "    LDX $123456",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x0000, 0xAE), (0x0001, 0x56), (0x0002, 0x34)]
    );

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume dbr=$00", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    LDX $123456", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume dbr=$00"));
}

#[test]
fn m65816_assume_dbr_rejects_low_bank_symbol_for_non_long_mnemonics() {
    let mut symbols = SymbolTable::new();
    assert_eq!(
        symbols.add("target", 0x0040, false, SymbolVisibility::Private, None),
        SymbolTableResult::Ok
    );
    assert_eq!(symbols.update("target", 0x0040), SymbolTableResult::Ok);
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume dbr=$12", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    LDX target", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume dbr=$12"));
}

#[test]
fn m65816_forward_label_uses_dbr_for_unresolved_long_sizing() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0100",
        ".assume pbr=$34, dbr=$00",
        "start:",
        "    LDA target",
        "    NOP",
        "target:",
        "    RTL",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0100, 0xAD),
            (0x0101, 0x04),
            (0x0102, 0x01),
            (0x0103, 0xEA),
            (0x0104, 0x6B),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0104));

    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0100",
        ".assume dbr=$12",
        "start:",
        "    LDA target",
        "    NOP",
        "target:",
        "    RTL",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0100, 0xAF),
            (0x0101, 0x05),
            (0x0102, 0x01),
            (0x0103, 0x00),
            (0x0104, 0xEA),
            (0x0105, 0x6B),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0105));
}

#[test]
fn m65816_forward_label_x_index_uses_dbr_for_unresolved_long_sizing() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0100",
        ".assume pbr=$34, dbr=$00",
        "start:",
        "    LDA target,X",
        "    NOP",
        "target:",
        "    RTL",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0100, 0xBD),
            (0x0101, 0x04),
            (0x0102, 0x01),
            (0x0103, 0xEA),
            (0x0104, 0x6B),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0104));

    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0100",
        ".assume dbr=$12",
        "start:",
        "    LDA target,X",
        "    NOP",
        "target:",
        "    RTL",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0100, 0xBF),
            (0x0101, 0x05),
            (0x0102, 0x01),
            (0x0103, 0x00),
            (0x0104, 0xEA),
            (0x0105, 0x6B),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0105));
}

#[test]
fn m65816_assume_dp_maps_16bit_operands_to_direct_page_modes() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$2000",
        "    LDA $20F0",
        "    LDA $20E0,X",
        "    ORA [$20D0]",
        "    ORA [$20C0],Y",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA5),
            (0x0001, 0xF0),
            (0x0002, 0xB5),
            (0x0003, 0xE0),
            (0x0004, 0x07),
            (0x0005, 0xD0),
            (0x0006, 0x17),
            (0x0007, 0xC0),
        ]
    );
}

#[test]
fn m65816_assume_dp_maps_parenthesized_direct_page_modes() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$2000",
        "    LDA ($20F0),Y",
        "    LDA ($20E0,X)",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xB1),
            (0x0001, 0xF0),
            (0x0002, 0xA1),
            (0x0003, 0xE0),
        ]
    );
}

#[test]
fn m65816_tcd_invalidates_direct_page_without_value_tracking() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        "    REP #$20",
        "    LDA #$2000",
        "    TCD",
        "    LDA $20AA",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x20),
            (0x0002, 0xA9),
            (0x0003, 0x00),
            (0x0004, 0x20),
            (0x0005, 0x5B),
            (0x0006, 0xAD),
            (0x0007, 0xAA),
            (0x0008, 0x20),
        ]
    );
}

#[test]
fn m65816_tcd_with_unknown_a_clears_direct_page_assumption() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$2000",
        "    LDA #$12",
        "    TCD",
        "    LDA $20AA",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x5B),
            (0x0003, 0xAD),
            (0x0004, 0xAA),
            (0x0005, 0x20),
        ]
    );
}

#[test]
fn m65816_pea_pld_does_not_infer_direct_page_from_pushed_literal() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$0000",
        "    PEA $20AA",
        "    PLD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xF4),
            (0x0001, 0xAA),
            (0x0002, 0x20),
            (0x0003, 0x2B),
            (0x0004, 0xAD),
            (0x0005, 0xCC),
            (0x0006, 0x20),
        ]
    );
}

#[test]
fn m65816_pea_pld_inference_is_cleared_by_intervening_stack_mutation() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$0000",
        "    PEA $20AA",
        "    PHA",
        "    PLD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xF4),
            (0x0001, 0xAA),
            (0x0002, 0x20),
            (0x0003, 0x48),
            (0x0004, 0x2B),
            (0x0005, 0xAD),
            (0x0006, 0xCC),
            (0x0007, 0x20),
        ]
    );
}

#[test]
fn m65816_phd_pld_invalidates_direct_page_assumption() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$2000",
        "    PHD",
        "    PLD",
        "    LDA $20AA",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x0B),
            (0x0001, 0x2B),
            (0x0002, 0xAD),
            (0x0003, 0xAA),
            (0x0004, 0x20),
        ]
    );
}

#[test]
fn m65816_phd_pld_preserves_unknown_direct_page_state() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$2000",
        "    LDA #$12",
        "    TCD",
        "    PHD",
        "    PLD",
        "    LDA $20AA",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x5B),
            (0x0003, 0x0B),
            (0x0004, 0x2B),
            (0x0005, 0xAD),
            (0x0006, 0xAA),
            (0x0007, 0x20),
        ]
    );
}

#[test]
fn m65816_lda_imm16_pha_pld_does_not_infer_direct_page_when_accumulator_is_16bit() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$0000",
        "    REP #$20",
        "    LDA #$20AA",
        "    PHA",
        "    PLD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x20),
            (0x0002, 0xA9),
            (0x0003, 0xAA),
            (0x0004, 0x20),
            (0x0005, 0x48),
            (0x0006, 0x2B),
            (0x0007, 0xAD),
            (0x0008, 0xCC),
            (0x0009, 0x20),
        ]
    );
}

#[test]
fn m65816_lda_imm16_pha_pld_does_not_infer_when_sep_forces_8bit_push() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$0000",
        "    REP #$20",
        "    LDA #$20AA",
        "    SEP #$20",
        "    PHA",
        "    PLD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x20),
            (0x0002, 0xA9),
            (0x0003, 0xAA),
            (0x0004, 0x20),
            (0x0005, 0xE2),
            (0x0006, 0x20),
            (0x0007, 0x48),
            (0x0008, 0x2B),
            (0x0009, 0xAD),
            (0x000A, 0xCC),
            (0x000B, 0x20),
        ]
    );
}

#[test]
fn m65816_tdc_tcd_does_not_preserve_known_direct_page_state_without_inference() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$20AA",
        "    TDC",
        "    TCD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x7B),
            (0x0001, 0x5B),
            (0x0002, 0xAD),
            (0x0003, 0xCC),
            (0x0004, 0x20),
        ]
    );
}

#[test]
fn m65816_tdc_tcd_does_not_restore_stale_direct_page_when_unknown() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$20AA",
        "    LDA #$12",
        "    TCD",
        "    TDC",
        "    TCD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xA9),
            (0x0001, 0x12),
            (0x0002, 0x5B),
            (0x0003, 0x7B),
            (0x0004, 0x5B),
            (0x0005, 0xAD),
            (0x0006, 0xCC),
            (0x0007, 0x20),
        ]
    );
}

#[test]
fn m65816_tdc_pha_pld_does_not_infer_direct_page_when_accumulator_is_16bit() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume dp=$20AA",
        "    REP #$20",
        "    TDC",
        "    PHA",
        "    PLD",
        "    LDA $20CC",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0xC2),
            (0x0001, 0x20),
            (0x0002, 0x7B),
            (0x0003, 0x48),
            (0x0004, 0x2B),
            (0x0005, 0xAD),
            (0x0006, 0xCC),
            (0x0007, 0x20),
        ]
    );
}

#[test]
fn m65816_assume_pbr_controls_24bit_jmp_operands() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12",
        "    JMP $123456",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x0000, 0x4C), (0x0001, 0x56), (0x0002, 0x34)]
    );

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$00", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP $123456", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$00"));
}

#[test]
fn m65816_assume_pbr_auto_restores_inferred_behavior() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $340000",
        ".assume pbr=$00",
        ".assume pbr=auto",
        "    JMP $343210",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x340000, 0x4C), (0x340001, 0x10), (0x340002, 0x32)]
    );
}

#[test]
fn m65816_default_pbr_follows_current_address_bank() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $340000",
        "    JMP $343210",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x340000, 0x4C), (0x340001, 0x10), (0x340002, 0x32)]
    );
}

#[test]
fn m65816_cpu_switch_reset_restores_inferred_pbr_bank() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".assume pbr=$12",
        ".cpu 6502",
        ".cpu 65816",
        ".org $340000",
        "    JMP $343210",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![(0x340000, 0x4C), (0x340001, 0x10), (0x340002, 0x32)]
    );
}

#[test]
fn m65816_assume_pbr_rejects_low_bank_symbol_for_jmp_forms() {
    let mut symbols = SymbolTable::new();
    assert_eq!(
        symbols.add("target", 0x0040, false, SymbolVisibility::Private, None),
        SymbolTableResult::Ok
    );
    assert_eq!(symbols.update("target", 0x0040), SymbolTableResult::Ok);
    let registry = default_registry();

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$12", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP target", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$12"));

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$12", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP (target)", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$12"));

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$12", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP (target,X)", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$12"));
}

#[test]
fn m65816_assume_pbr_controls_24bit_jmp_indirect_operands() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $0000",
        ".assume pbr=$12",
        "    JMP ($123456)",
        "    JMP ($123456,X)",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0000, 0x6C),
            (0x0001, 0x56),
            (0x0002, 0x34),
            (0x0003, 0x7C),
            (0x0004, 0x56),
            (0x0005, 0x34),
        ]
    );

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$00", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP ($123456)", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$00"));

    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);
    assert_eq!(
        process_line(&mut asm, ".assume pbr=$00", 0, 2),
        LineStatus::Ok
    );
    let status = process_line(&mut asm, "    JMP ($123456,X)", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".assume pbr=$00"));
}

#[test]
fn m65816_alias_directives_set_runtime_state() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $120000",
        ".al",
        ".xl",
        ".databank auto",
        ".dpage $2000",
        "    LDA #$1234",
        "    LDX #$5678",
        "    LDA $123456,l",
        "    LDA $20F0,d",
        "    JMP $123210,k",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x120000, 0xA9),
            (0x120001, 0x34),
            (0x120002, 0x12),
            (0x120003, 0xA2),
            (0x120004, 0x78),
            (0x120005, 0x56),
            (0x120006, 0xAF),
            (0x120007, 0x56),
            (0x120008, 0x34),
            (0x120009, 0x12),
            (0x12000A, 0xA5),
            (0x12000B, 0xF0),
            (0x12000C, 0x4C),
            (0x12000D, 0x10),
            (0x12000E, 0x32),
        ]
    );
}

#[test]
fn m65816_alias_directives_validate_operands() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, ".al 1", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".al does not accept operands"));

    let status = process_line(&mut asm, ".databank", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains(".databank expects 1 operand"));
}

#[test]
fn m65816_explicit_long_override_wins_over_assume_bank_choice() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $120000",
        ".assume dbr=auto",
        "    LDA $123456,l",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x120000, 0xAF),
            (0x120001, 0x56),
            (0x120002, 0x34),
            (0x120003, 0x12),
        ]
    );
}

#[test]
fn m65816_explicit_force_rejects_invalid_context() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 65816", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    LDA $123456,k", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains("Explicit addressing override ',k' is not valid"));

    let status = process_line(&mut asm, "    JMP $123456,b", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm
        .error_message()
        .contains("Explicit addressing override ',b' is not valid"));
}

#[test]
fn m6502_rejects_65816_explicit_override_suffixes() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    assert_eq!(process_line(&mut asm, ".cpu 6502", 0, 2), LineStatus::Ok);

    let status = process_line(&mut asm, "    LDA $10,d", 0, 2);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("65816-only addressing mode"));
}

#[test]
fn m65816_stack_relative_forms_encode() {
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA $10,S"),
        vec![0x03, 0x10]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA ($20,S),Y"),
        vec![0x13, 0x20]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA $11,S"),
        vec![0xA3, 0x11]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA ($21,S),Y"),
        vec![0xB3, 0x21]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA $12,S"),
        vec![0x83, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA ($22,S),Y"),
        vec![0x93, 0x22]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ADC $13,S"),
        vec![0x63, 0x13]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    AND ($24,S),Y"),
        vec![0x33, 0x24]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    EOR $25,S"),
        vec![0x43, 0x25]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    CMP ($26,S),Y"),
        vec![0xD3, 0x26]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    SBC ($23,S),Y"),
        vec![0xF3, 0x23]
    );
}

#[test]
fn m65816_long_memory_forms_encode() {
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA $123456"),
        vec![0x0F, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA $123456,X"),
        vec![0x1F, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA $123456"),
        vec![0xAF, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA $123456,X"),
        vec![0xBF, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA $123456"),
        vec![0x8F, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA $123456,X"),
        vec![0x9F, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ADC $123456"),
        vec![0x6F, 0x56, 0x34, 0x12]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    SBC $123456,X"),
        vec![0xFF, 0x56, 0x34, 0x12]
    );
}

#[test]
fn m65816_forward_high_bank_label_uses_stable_long_sizing() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".org $123400",
        "start:",
        "    LDA target",
        "    NOP",
        "target:",
        "    RTL",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x123400, 0xAF),
            (0x123401, 0x05),
            (0x123402, 0x34),
            (0x123403, 0x12),
            (0x123404, 0xEA),
            (0x123405, 0x6B),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x123405));
}

#[test]
fn bss_reserve_wide_size_places_symbol_above_64k() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".region ram, $010000, $04FFFF",
        ".section vars, kind=bss",
        "start:",
        "    .res long, 20000",
        "end_label:",
        ".endsection",
        ".place vars in ram",
        ".endmodule",
    ]);

    assert_eq!(assembler.symbols().lookup("main.start"), Some(0x010000));
    assert_eq!(assembler.symbols().lookup("main.end_label"), Some(0x023880));
    assert_eq!(assembler.image().num_entries(), 0);
}

#[test]
fn m6502_forward_boundary_label_uses_stable_absolute_sizing() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 6502",
        ".org $00FD",
        "start:",
        "    LDA target",
        "    NOP",
        "target:",
        "    RTS",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x00FD, 0xAD),
            (0x00FE, 0x01),
            (0x00FF, 0x01),
            (0x0100, 0xEA),
            (0x0101, 0x60),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0101));
}

#[test]
fn m65c02_forward_boundary_label_uses_stable_absolute_sizing() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65c02",
        ".org $00FD",
        "start:",
        "    STZ target",
        "    NOP",
        "target:",
        "    RTS",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x00FD, 0x9C),
            (0x00FE, 0x01),
            (0x00FF, 0x01),
            (0x0100, 0xEA),
            (0x0101, 0x60),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.target"), Some(0x0101));
}

#[test]
fn m6502_branch_in_packed_section_uses_rebased_address_before_pack_line() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 6502",
        ".region c64, $0801, $08FF",
        ".section code, align=1",
        "start:",
        "    BEQ done",
        "    NOP",
        "done:",
        "    RTS",
        ".endsection",
        ".pack in c64 : code",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x0801, 0xF0),
            (0x0802, 0x01),
            (0x0803, 0xEA),
            (0x0804, 0x60),
        ]
    );
    assert_eq!(assembler.symbols().lookup("main.start"), Some(0x0801));
    assert_eq!(assembler.symbols().lookup("main.done"), Some(0x0804));
}

#[test]
fn m65816_direct_page_indirect_long_forms_encode() {
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA [$10]"),
        vec![0x07, 0x10]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ORA [$10],Y"),
        vec![0x17, 0x10]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA [$20]"),
        vec![0xA7, 0x20]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    LDA [$20],Y"),
        vec![0xB7, 0x20]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA [$30]"),
        vec![0x87, 0x30]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    STA [$30],Y"),
        vec![0x97, 0x30]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    ADC [$40],Y"),
        vec![0x77, 0x40]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    SBC [$50]"),
        vec![0xE7, 0x50]
    );
}

#[test]
fn m65816_effective_opcode_space_covers_all_256_opcodes() {
    let is_disallowed_m65c02_mnemonic = |mnemonic: &str| {
        matches!(
            mnemonic,
            "RMB0"
                | "RMB1"
                | "RMB2"
                | "RMB3"
                | "RMB4"
                | "RMB5"
                | "RMB6"
                | "RMB7"
                | "SMB0"
                | "SMB1"
                | "SMB2"
                | "SMB3"
                | "SMB4"
                | "SMB5"
                | "SMB6"
                | "SMB7"
                | "BBR0"
                | "BBR1"
                | "BBR2"
                | "BBR3"
                | "BBR4"
                | "BBR5"
                | "BBR6"
                | "BBR7"
                | "BBS0"
                | "BBS1"
                | "BBS2"
                | "BBS3"
                | "BBS4"
                | "BBS5"
                | "BBS6"
                | "BBS7"
        )
    };

    let mut by_mnemonic_mode: HashMap<(String, String), u8> = HashMap::new();

    for entry in FAMILY_INSTRUCTION_TABLE {
        by_mnemonic_mode.insert(
            (entry.mnemonic.to_string(), format!("{:?}", entry.mode)),
            entry.opcode,
        );
    }

    for entry in M65C02_INSTRUCTION_TABLE {
        if is_disallowed_m65c02_mnemonic(entry.mnemonic) {
            continue;
        }
        by_mnemonic_mode.insert(
            (entry.mnemonic.to_string(), format!("{:?}", entry.mode)),
            entry.opcode,
        );
    }

    for entry in M65816_INSTRUCTION_TABLE {
        by_mnemonic_mode.insert(
            (entry.mnemonic.to_string(), format!("{:?}", entry.mode)),
            entry.opcode,
        );
    }

    let mut covered = [false; 256];
    for opcode in by_mnemonic_mode.values() {
        covered[*opcode as usize] = true;
    }

    let missing: Vec<usize> = covered
        .iter()
        .enumerate()
        .filter_map(|(opcode, present)| if *present { None } else { Some(opcode) })
        .collect();

    assert!(
        missing.is_empty(),
        "missing effective 65816 opcodes: {missing:?}"
    );
}

#[test]
fn legacy_cpus_reject_65816_mnemonics_and_modes() {
    let (status, message) = assemble_line_status(m6502_cpu_id, "    BRL $0005");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("No instruction found for BRL"));

    let (status, message) = assemble_line_status(m65c02_cpu_id, "    ORA $10,S");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("65816-only addressing mode not supported on 65C02"));

    let (status, message) = assemble_line_status(m6502_cpu_id, "    JSL $123456");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.contains("No instruction found for JSL") || message.contains("out of 16-bit range")
    );

    let (status, message) = assemble_line_status(m65c02_cpu_id, "    MVN $01,$02");
    assert_eq!(status, LineStatus::Error);
    let message = message.unwrap_or_default();
    assert!(
        message.contains("65816-only addressing mode not supported on 65C02")
            || message.contains("No instruction found for MVN")
    );

    let (status, message) = assemble_line_status(m65c02_cpu_id, "    PEA $1234");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("No instruction found for PEA"));
}

#[test]
fn m65816_rejects_m65c02_only_bit_branch_and_bit_memory_mnemonics() {
    let (status, message) = assemble_line_status(m65816_cpu_id, "    RMB0 $12");
    assert_eq!(status, LineStatus::Error);
    assert!(message.unwrap_or_default().contains("RMB0"));

    let (status, message) = assemble_line_status(m65816_cpu_id, "    SMB7 $12");
    assert_eq!(status, LineStatus::Error);
    assert!(message.unwrap_or_default().contains("SMB7"));

    let (status, message) = assemble_line_status(m65816_cpu_id, "    BBR0 $12,$34");
    assert_eq!(status, LineStatus::Error);
    assert!(message.unwrap_or_default().contains("BBR0"));

    let (status, message) = assemble_line_status(m65816_cpu_id, "    BBS7 $12,$34");
    assert_eq!(status, LineStatus::Error);
    assert!(message.unwrap_or_default().contains("BBS7"));
}

#[test]
fn m65816_brl_per_boundary_offsets() {
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    BRL $8002"),
        vec![0x82, 0xFF, 0x7F]
    );
    assert_eq!(
        assemble_bytes(m65816_cpu_id, "    PER $8002"),
        vec![0x62, 0xFF, 0x7F]
    );

    let (status, message) = assemble_line_status(m65816_cpu_id, "    BRL $8003");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("Long branch target out of range"));

    let (status, message) = assemble_line_status(m65816_cpu_id, "    PER $8003");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("Long branch target out of range"));
}

#[test]
fn mixed_cpu_switching_with_65816_aliases() {
    let assembler = run_passes(&[
        ".module main",
        ".org $1000",
        ".cpu 6502",
        "    RTS",
        ".cpu 65816",
        "    REP #$30",
        "    ORA $10,S",
        ".cpu 65c02",
        "    STZ $20",
        ".cpu 65c816",
        "    MVN $01,$02",
        ".cpu w65c816",
        "    RTL",
        ".endmodule",
    ]);

    let entries = assembler.image().entries().expect("image entries");
    assert_eq!(
        entries,
        vec![
            (0x1000, 0x60),
            (0x1001, 0xC2),
            (0x1002, 0x30),
            (0x1003, 0x03),
            (0x1004, 0x10),
            (0x1005, 0x64),
            (0x1006, 0x20),
            (0x1007, 0x54),
            (0x1008, 0x01),
            (0x1009, 0x02),
            (0x100A, 0x6B),
        ]
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
    let range = spec.range.as_ref().expect("range");
    assert_eq!(range.start, 0x0000);
    assert_eq!(range.end, 0x0003);
    assert_eq!(output.fill_byte, Some(0xaa));
}

#[test]
fn root_metadata_bin_allows_empty_value() {
    let lines = vec![
        ".module main".to_string(),
        ".meta.output.bin".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);
    let output = assembler.root_metadata.output_config_for_cpu("i8085");
    assert_eq!(output.bin_specs.len(), 1);
    let spec = &output.bin_specs[0];
    assert!(spec.name.is_none());
    assert!(spec.range.is_none());
}

#[test]
fn root_metadata_mapfile_directives_are_stored() {
    let lines = vec![
        ".module main".to_string(),
        ".mapfile \"build/default.map\"".to_string(),
        ".mapfile \"build/public.map\", symbols=public".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);

    assert_eq!(assembler.root_metadata.mapfiles.len(), 2);
    assert_eq!(
        assembler.root_metadata.mapfiles[0].path,
        "build/default.map"
    );
    assert_eq!(
        assembler.root_metadata.mapfiles[0].symbols,
        MapSymbolsMode::None
    );
    assert_eq!(assembler.root_metadata.mapfiles[1].path, "build/public.map");
    assert_eq!(
        assembler.root_metadata.mapfiles[1].symbols,
        MapSymbolsMode::Public
    );
}

#[test]
fn mapfile_rejects_invalid_symbols_value() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".module main", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".mapfile \"build/a.map\", symbols=private", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
}

#[test]
fn root_metadata_exportsections_directive_is_stored() {
    let lines = vec![
        ".module main".to_string(),
        ".exportsections dir=\"build/sections\", format=bin".to_string(),
        ".exportsections dir=\"build/sections-all\", format=bin, include=bss".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);

    assert_eq!(assembler.root_metadata.export_sections.len(), 2);
    assert_eq!(
        assembler.root_metadata.export_sections[0].dir,
        "build/sections"
    );
    assert_eq!(
        assembler.root_metadata.export_sections[0].format,
        ExportSectionsFormat::Bin
    );
    assert_eq!(
        assembler.root_metadata.export_sections[0].include,
        ExportSectionsInclude::NoBss
    );
    assert_eq!(
        assembler.root_metadata.export_sections[1].dir,
        "build/sections-all"
    );
    assert_eq!(
        assembler.root_metadata.export_sections[1].format,
        ExportSectionsFormat::Bin
    );
    assert_eq!(
        assembler.root_metadata.export_sections[1].include,
        ExportSectionsInclude::Bss
    );
}

#[test]
fn exportsections_requires_format_option() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".module main", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, ".exportsections dir=\"build/sections\"", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
}

#[test]
fn root_metadata_linker_output_directive_is_stored() {
    let lines = vec![
        ".module main".to_string(),
        ".output \"build/game.prg\", format=prg, sections=code,data".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);

    assert_eq!(assembler.root_metadata.linker_outputs.len(), 1);
    let output = &assembler.root_metadata.linker_outputs[0];
    assert_eq!(output.path, "build/game.prg");
    assert_eq!(output.format, LinkerOutputFormat::Prg);
    assert_eq!(
        output.sections,
        vec!["code".to_string(), "data".to_string()]
    );
    assert!(output.contiguous);
    assert_eq!(output.image_start, None);
    assert_eq!(output.image_end, None);
    assert_eq!(output.fill, None);
    assert_eq!(output.loadaddr, None);
}

#[test]
fn root_metadata_linker_output_image_mode_is_stored() {
    let lines = vec![
            ".module main".to_string(),
            ".output \"build/rom.bin\", format=bin, image=\"$8000..$80ff\", fill=$ff, contiguous=false, loadaddr=$8000, sections=code,data".to_string(),
            ".endmodule".to_string(),
        ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);

    assert_eq!(assembler.root_metadata.linker_outputs.len(), 1);
    let output = &assembler.root_metadata.linker_outputs[0];
    assert_eq!(output.path, "build/rom.bin");
    assert_eq!(output.format, LinkerOutputFormat::Bin);
    assert_eq!(
        output.sections,
        vec!["code".to_string(), "data".to_string()]
    );
    assert!(!output.contiguous);
    assert_eq!(output.image_start, Some(0x8000));
    assert_eq!(output.image_end, Some(0x80ff));
    assert_eq!(output.fill, Some(0xff));
    assert_eq!(output.loadaddr, Some(0x8000));
}

#[test]
fn root_metadata_linker_output_wide_image_mode_is_stored() {
    let lines = vec![
        ".module main".to_string(),
        ".output \"build/rom.bin\", format=bin, image=\"$123400..$1234ff\", fill=$ff, contiguous=false, loadaddr=$123456, sections=code".to_string(),
        ".endmodule".to_string(),
    ];
    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    let _ = assembler.pass1(&lines);

    assert_eq!(assembler.root_metadata.linker_outputs.len(), 1);
    let output = &assembler.root_metadata.linker_outputs[0];
    assert_eq!(output.image_start, Some(0x123400));
    assert_eq!(output.image_end, Some(0x1234ff));
    assert_eq!(output.loadaddr, Some(0x123456));
}

#[test]
fn linker_output_fill_requires_image() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, ".module main", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(
        &mut asm,
        ".output \"build/game.bin\", format=bin, fill=$ff, sections=code",
        0,
        1,
    );
    assert_eq!(status, LineStatus::Error);
    assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
}

#[test]
fn linker_output_contiguous_bundle_success() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a",
        ".byte $aa",
        ".endsection",
        ".section b",
        ".byte $bb",
        ".endsection",
        ".place a in ram",
        ".place b in ram",
        ".output \"build/out.bin\", format=bin, sections=a,b",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let payload = build_linker_output_payload(output, assembler.sections()).expect("bundle");
    assert_eq!(payload, vec![0xaa, 0xbb]);
}

#[test]
fn linker_output_contiguous_bundle_rejects_gap() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a, align=1",
        ".byte $aa",
        ".endsection",
        ".section b, align=2",
        ".byte $bb",
        ".endsection",
        ".place a in ram",
        ".place b in ram",
        ".output \"build/out.bin\", format=bin, sections=a,b",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let err =
        build_linker_output_payload(output, assembler.sections()).expect_err("gap should fail");
    assert_eq!(err.kind(), AsmErrorKind::Directive);
    assert!(err.message().contains("contiguous output"));
    assert!(err.message().contains("gap $1001..$1001"));
    assert!(err.message().ends_with(": b"));
}

#[test]
fn linker_output_image_mode_fill_copies_sections() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a, align=1",
        ".byte $aa",
        ".endsection",
        ".section b, align=2",
        ".byte $bb",
        ".endsection",
        ".place a in ram",
        ".place b in ram",
        ".output \"build/out.bin\", format=bin, image=\"$1000..$1003\", fill=$ff, contiguous=false, sections=a,b",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let payload = build_linker_output_payload(output, assembler.sections()).expect("image");
    assert_eq!(payload, vec![0xaa, 0xff, 0xbb, 0xff]);
}

#[test]
fn linker_output_image_mode_rejects_out_of_span_section() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a, align=1",
        ".byte $aa",
        ".endsection",
        ".section b, align=2",
        ".byte $bb",
        ".endsection",
        ".place a in ram",
        ".place b in ram",
        ".output \"build/out.bin\", format=bin, image=\"$1000..$1001\", fill=$ff, sections=a,b",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let err = build_linker_output_payload(output, assembler.sections())
        .expect_err("out-of-span should fail");
    assert_eq!(err.kind(), AsmErrorKind::Directive);
    assert!(err.message().contains("outside image span"));
}

#[test]
fn linker_output_prg_prefixes_default_loadaddr() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a",
        ".byte $aa",
        ".endsection",
        ".place a in ram",
        ".output \"build/out.prg\", format=prg, sections=a",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let payload = build_linker_output_payload(output, assembler.sections()).expect("prg");
    assert_eq!(payload, vec![0x00, 0x10, 0xaa]);
}

#[test]
fn linker_output_prg_rejects_wide_loadaddr() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section a",
        ".byte $aa",
        ".endsection",
        ".place a in ram",
        ".output \"build/out.prg\", format=prg, loadaddr=$123456, sections=a",
        ".endmodule",
    ]);
    let output = assembler
        .root_metadata
        .linker_outputs
        .first()
        .expect("output directive");
    let err = build_linker_output_payload(output, assembler.sections())
        .expect_err("wide PRG loadaddr should fail");
    assert_eq!(err.kind(), AsmErrorKind::Directive);
    assert!(err
        .message()
        .contains("PRG load address exceeds 16-bit range"));
}

#[test]
fn linker_output_image_mode_rejects_section_address_overflow() {
    let output = LinkerOutputDirective {
        path: "build/out.bin".to_string(),
        format: LinkerOutputFormat::Bin,
        sections: vec!["a".to_string()],
        contiguous: false,
        image_start: Some(u32::MAX - 1),
        image_end: Some(u32::MAX),
        fill: Some(0xff),
        loadaddr: None,
    };
    let mut sections = HashMap::new();
    let section = SectionState {
        base_addr: Some(u32::MAX),
        bytes: vec![0xaa, 0xbb],
        ..Default::default()
    };
    sections.insert("a".to_string(), section);

    let err = build_linker_output_payload(&output, &sections)
        .expect_err("address overflow should be rejected");
    assert_eq!(err.kind(), AsmErrorKind::Directive);
    assert!(err
        .message()
        .contains("Section address range overflows in .output"));
}

#[test]
fn linker_output_contiguous_mode_rejects_section_address_overflow() {
    let output = LinkerOutputDirective {
        path: "build/out.bin".to_string(),
        format: LinkerOutputFormat::Bin,
        sections: vec!["a".to_string()],
        contiguous: true,
        image_start: None,
        image_end: None,
        fill: None,
        loadaddr: None,
    };
    let mut sections = HashMap::new();
    let section = SectionState {
        base_addr: Some(u32::MAX),
        bytes: vec![0xaa, 0xbb],
        ..Default::default()
    };
    sections.insert("a".to_string(), section);

    let err = build_linker_output_payload(&output, &sections)
        .expect_err("address overflow should be rejected");
    assert_eq!(err.kind(), AsmErrorKind::Directive);
    assert!(err
        .message()
        .contains("Section address range overflows in contiguous output"));
}

#[test]
fn exportsections_default_excludes_bss() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section code",
        ".byte $aa",
        ".endsection",
        ".section zero, kind=bss",
        ".res byte, 2",
        ".endsection",
        ".place code in ram",
        ".place zero in ram",
        ".exportsections dir=\"build/sections\", format=bin",
        ".endmodule",
    ]);
    let directive = assembler
        .root_metadata
        .export_sections
        .first()
        .expect("exportsections");
    let files = build_export_sections_payloads(directive, assembler.sections());
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "code.bin");
    assert_eq!(files[0].1, vec![0xaa]);
}

#[test]
fn exportsections_include_bss_exports_all_sections() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section code",
        ".byte $aa",
        ".endsection",
        ".section zero, kind=bss",
        ".res byte, 2",
        ".endsection",
        ".place code in ram",
        ".place zero in ram",
        ".exportsections dir=\"build/sections\", format=bin, include=bss",
        ".endmodule",
    ]);
    let directive = assembler
        .root_metadata
        .export_sections
        .first()
        .expect("exportsections");
    let files = build_export_sections_payloads(directive, assembler.sections());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].0, "code.bin");
    assert_eq!(files[0].1, vec![0xaa]);
    assert_eq!(files[1].0, "zero.bin");
    assert!(files[1].1.is_empty());
}

#[test]
fn mapfile_public_mode_only_lists_public_symbols() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section code",
        "priv_label: .byte $aa",
        ".pub",
        "pub_label: .byte $bb",
        ".priv",
        ".endsection",
        ".place code in ram",
        ".mapfile \"build/public.map\", symbols=public",
        ".endmodule",
    ]);
    let directive = assembler.root_metadata.mapfiles.first().expect("mapfile");
    let map = build_mapfile_text(
        directive,
        assembler.regions(),
        assembler.sections(),
        assembler.symbols(),
    );
    assert!(map.contains("Regions"));
    assert!(map.contains("Sections"));
    assert!(map.contains("code 1000 2 code ram"));
    assert!(map.contains("Symbols"));
    assert!(map.contains("pub_label"));
    assert!(!map.contains("priv_label"));
}

#[test]
fn mapfile_all_and_none_modes_control_symbol_listing() {
    let assembler = run_passes(&[
        ".module main",
        ".region ram, $1000, $10ff",
        ".section code",
        "priv_label: .byte $aa",
        ".pub",
        "pub_label: .byte $bb",
        ".priv",
        ".endsection",
        ".place code in ram",
        ".mapfile \"build/all.map\", symbols=all",
        ".mapfile \"build/none.map\"",
        ".endmodule",
    ]);
    let all_directive = &assembler.root_metadata.mapfiles[0];
    let none_directive = &assembler.root_metadata.mapfiles[1];
    let all_map = build_mapfile_text(
        all_directive,
        assembler.regions(),
        assembler.sections(),
        assembler.symbols(),
    );
    let none_map = build_mapfile_text(
        none_directive,
        assembler.regions(),
        assembler.sections(),
        assembler.symbols(),
    );
    assert!(all_map.contains("pub_label"));
    assert!(all_map.contains("priv_label"));
    assert!(!none_map.contains("Symbols"));
}

#[test]
fn mapfile_formats_wide_values_without_truncation() {
    let assembler = run_passes(&[
        ".module main",
        ".cpu 65816",
        ".region hi, $FF0000, $FF00FF",
        "wide_const .const $89ABCDEF",
        "wide_var .var $01234567",
        ".section code",
        "entry: .byte $ea",
        ".endsection",
        ".place code in hi",
        ".mapfile \"build/wide.map\", symbols=all",
        ".endmodule",
    ]);
    let directive = assembler.root_metadata.mapfiles.first().expect("mapfile");
    let map = build_mapfile_text(
        directive,
        assembler.regions(),
        assembler.sections(),
        assembler.symbols(),
    );
    assert!(map.contains("hi FF0000 FF00FF"));
    assert!(map.contains("code FF0000 1 code hi"));
    assert!(map.contains("main.entry FF0000 private"));
    assert!(map.contains("main.wide_const 89ABCDEF private"));
    assert!(map.contains("main.wide_var 01234567 private"));
}

#[test]
fn mapfile_region_usage_supports_full_u32_span_without_saturation() {
    let directive = MapFileDirective {
        path: "build/full.map".to_string(),
        symbols: MapSymbolsMode::None,
    };
    let mut regions = HashMap::new();
    regions.insert(
        "full".to_string(),
        RegionState {
            name: "full".to_string(),
            start: 0,
            end: u32::MAX,
            cursor: u32::MAX,
            align: 1,
            placed: Vec::new(),
        },
    );

    let map = build_mapfile_text(&directive, &regions, &HashMap::new(), &SymbolTable::new());
    assert!(map.contains("full 0000 FFFFFFFF 4294967295 1 1"), "{map}");
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
    let metadata = RootMetadata {
        root_module_id: Some("main".to_string()),
        ..RootMetadata::default()
    };
    let mut asm = AsmLine::with_cpu_and_metadata(&mut symbols, i8085_cpu_id, &registry, metadata);
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
    let metadata = RootMetadata {
        root_module_id: Some("main".to_string()),
        ..RootMetadata::default()
    };
    let mut asm = AsmLine::with_cpu_and_metadata(&mut symbols, i8085_cpu_id, &registry, metadata);
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
fn label_with_colon_is_still_supported() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);
    let status = process_line(&mut asm, "LABEL: NOP", 0x1200, 1);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.symbols().lookup("LABEL"), Some(0x1200));
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
fn instruction_immediate_accepts_0b8h_literal() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let status = process_line(&mut asm, "    LDA #0B8H", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0xA9, 0xB8]);
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
    let mut addr: u32 = 0;
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
                addr = addr.wrapping_add(asm.num_bytes() as u32);
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
    let mut addr: u32 = 0;
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
                addr = addr.wrapping_add(asm.num_bytes() as u32);
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

#[cfg(feature = "vm-parity")]
#[test]
fn vm_parity_smoke_instruction_bytes_and_diagnostics() {
    use crate::vm::builder::build_hierarchy_package_from_registry;
    use crate::vm::package::load_hierarchy_package;
    use std::fs;
    use std::path::Path;

    let registry = default_registry();
    let package_bytes =
        build_hierarchy_package_from_registry(&registry).expect("build hierarchy package");
    let package = load_hierarchy_package(&package_bytes).expect("load hierarchy package");
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vm/vectors");
    let mut vector_paths: Vec<_> = fs::read_dir(vectors_dir)
        .expect("read vectors dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "optst"))
        .collect();
    vector_paths.sort();

    for vector_path in vector_paths {
        let content = fs::read_to_string(&vector_path).expect("read vector");
        let mut fields = std::collections::HashMap::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                fields.insert(key.trim().to_string(), value.trim_end().to_string());
            }
        }

        let cpu_name = fields.get("cpu").expect("cpu field");
        let cpu = registry
            .resolve_cpu_name(cpu_name)
            .expect("cpu must exist in registry");
        let expected_dialect = fields.get("dialect").expect("dialect field");
        let native_line = fields.get("native_line").expect("native_line field");
        let canonical_line = fields.get("canonical_line").expect("canonical_line field");
        let expect_status = fields.get("expect_status").expect("expect_status field");

        let resolved = package
            .resolve_pipeline(cpu.as_str(), None)
            .expect("pipeline should resolve");
        assert_eq!(
            resolved.dialect_id.to_ascii_lowercase(),
            expected_dialect.to_ascii_lowercase(),
            "vector {} resolved unexpected dialect",
            vector_path.display()
        );

        match expect_status.as_str() {
            "ok" => {
                let native_bytes = assemble_bytes(cpu, native_line);
                let package_path_bytes = assemble_bytes(cpu, canonical_line);
                assert_eq!(
                    native_bytes,
                    package_path_bytes,
                    "vector {} byte mismatch",
                    vector_path.display()
                );
            }
            "error" => {
                let (native_status, native_message) = assemble_line_status(cpu, native_line);
                let (package_status, package_message) = assemble_line_status(cpu, canonical_line);
                assert_eq!(
                    native_status,
                    package_status,
                    "vector {} status mismatch",
                    vector_path.display()
                );
                assert_eq!(
                    native_message,
                    package_message,
                    "vector {} diagnostic mismatch",
                    vector_path.display()
                );
            }
            other => panic!(
                "unsupported expect_status '{}' in {}",
                other,
                vector_path.display()
            ),
        }
    }
}

#[test]
fn vm_runtime_mos6502_base_cpu_path_uses_package_forms() {
    let bytes = assemble_bytes(m6502_cpu_id, "    LDA #$10");
    assert_eq!(bytes, vec![0xA9, 0x10]);

    let (status, message) = assemble_line_status(m6502_cpu_id, "    BRA $0000");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("no instruction found"));
}

#[test]
fn vm_runtime_model_is_available_for_mos6502_family_cpus() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    for cpu in [m6502_cpu_id, m65c02_cpu_id, m65816_cpu_id, m45gs02_cpu_id] {
        let asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
        assert!(
            asm.opthread_execution_model.is_some(),
            "expected runtime execution model for {}",
            cpu.as_str()
        );
    }
}

#[test]
fn vm_runtime_model_is_available_for_intel8080_family_cpus_for_vm_tokenization() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    let i8085_asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    assert!(i8085_asm.opthread_execution_model.is_some());

    let z80_asm = AsmLine::with_cpu(&mut symbols, z80_cpu_id, &registry);
    assert!(z80_asm.opthread_execution_model.is_some());
}

#[test]
fn vm_runtime_model_is_available_for_motorola6800_family_cpus() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    let m6809_asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);
    assert!(m6809_asm.opthread_execution_model.is_some());

    let hd6309_asm = AsmLine::with_cpu(&mut symbols, hd6309_cpu_id, &registry);
    assert!(hd6309_asm.opthread_execution_model.is_some());
}

#[cfg(feature = "vm-runtime-opcpu-artifact")]
#[test]
fn vm_runtime_artifact_path_is_target_relative() {
    let base = create_temp_dir("vm-artifact-path");
    let path = AsmLine::opthread_package_artifact_path_for_dir(base.as_path());
    assert_eq!(
        path,
        base.join("target")
            .join("vm")
            .join("opforge-vm-runtime.opcpu")
    );
}

#[cfg(feature = "vm-runtime-opcpu-artifact")]
#[test]
fn vm_runtime_artifact_helpers_round_trip_model_load() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let path = create_temp_dir("vm-artifact-roundtrip")
        .join("target")
        .join("vm")
        .join("opforge-vm-runtime.opcpu");
    let package_bytes =
        build_hierarchy_package_from_registry(&registry).expect("build hierarchy package");
    AsmLine::persist_opthread_package_artifact(path.as_path(), &package_bytes);

    let model = AsmLine::load_opthread_execution_model_from_artifact(path.as_path());
    assert!(
        model.is_some(),
        "expected runtime model from artifact bytes"
    );

    let asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
    assert!(
        asm.opthread_execution_model.is_some(),
        "runtime model should still initialize for authoritative family"
    );
}

#[cfg(feature = "vm-runtime-opcpu-artifact")]
#[test]
fn vm_runtime_artifact_mos6502_parity_and_determinism_gate() {
    let source = [
        "    .cpu 6502",
        "    .org $1000",
        "start:",
        "    LDA #<target",
        "    STA ptr",
        "    LDA #>target",
        "    STA ptr+1",
        "    BNE later",
        "ptr: .word target",
        "    .byte $EA,$EA",
        "later:",
        "    BEQ start",
        "target:",
        "    LDA #$42",
        "    RTS",
    ];

    let native = assemble_source_entries_with_runtime_mode(&source, false)
        .expect("native source assembly should run");
    let runtime_a = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("artifact runtime source assembly should run");
    let runtime_b = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("artifact runtime source re-run should be deterministic");

    assert_eq!(
        runtime_a.0, native.0,
        "artifact bytes/reloc parity mismatch"
    );
    assert_eq!(runtime_a.1, native.1, "artifact diagnostic parity mismatch");
    assert_eq!(
        runtime_b.0, runtime_a.0,
        "artifact runtime bytes are non-deterministic"
    );
    assert_eq!(
        runtime_b.1, runtime_a.1,
        "artifact runtime diagnostics are non-deterministic"
    );
}

#[test]
fn vm_rollout_criteria_all_registered_families_have_policy_and_checklist() {
    let registry = default_registry();
    for family in registry.family_ids() {
        let policy = family_runtime_rollout_policy(family.as_str())
            .unwrap_or_else(|| panic!("missing rollout policy for family '{}'", family.as_str()));
        assert!(
            !policy.migration_checklist.trim().is_empty(),
            "missing migration checklist for family '{}'",
            family.as_str()
        );
    }
}

#[test]
fn vm_rollout_criteria_intel_family_is_authoritative_when_runtime_enabled() {
    assert_eq!(
        family_runtime_mode("intel8080"),
        FamilyRuntimeMode::Authoritative
    );
    assert!(package_runtime_default_enabled_for_family("intel8080"));

    for (cpu, line) in [
        (i8085_cpu_id, "    MVI A,55h"),
        (z80_cpu_id, "    LD A,55h"),
    ] {
        let native = assemble_line_with_runtime_mode_no_injection(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode_no_injection(cpu, line, true);
        assert!(
            runtime.3,
            "authoritative family should initialize VM model for VM tokenization on {}",
            cpu.as_str()
        );
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_intel_authoritative_allows_lxi_register_named_label_as_immediate() {
    let source = ["    .cpu 8085", "SP: .word 256", "    LXI H,SP"];
    let (_entries, diagnostics) = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("source assembly should run");
    assert!(
        !diagnostics
            .iter()
            .any(|diag| diag.contains("expected 16-bit immediate, got register SP")),
        "unexpected LXI/SP immediate diagnostic: {diagnostics:?}"
    );
}

#[test]
fn vm_rollout_criteria_mos6502_parity_and_determinism_gate() {
    assert_eq!(
        family_runtime_mode("mos6502"),
        FamilyRuntimeMode::Authoritative
    );
    assert!(package_runtime_default_enabled_for_family("mos6502"));

    let source = [
        "    .cpu 6502",
        "    .org $1000",
        "start:",
        "    LDA #<target",
        "    STA ptr",
        "    LDA #>target",
        "    STA ptr+1",
        "    BNE later",
        "ptr: .word target",
        "    .byte $EA,$EA",
        "later:",
        "    BEQ start",
        "target:",
        "    LDA #$42",
        "    RTS",
    ];

    let native = assemble_source_entries_with_runtime_mode(&source, false)
        .expect("native source assembly should run");
    let runtime_a = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source assembly should run");
    let runtime_b = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source re-run should be deterministic");

    assert_eq!(runtime_a.0, native.0, "bytes/reloc parity mismatch");
    assert_eq!(runtime_a.1, native.1, "diagnostic parity mismatch");
    assert_eq!(
        runtime_b.0, runtime_a.0,
        "runtime bytes are non-deterministic"
    );
    assert_eq!(
        runtime_b.1, runtime_a.1,
        "runtime diagnostics are non-deterministic"
    );
}

#[test]
fn vm_rollout_criteria_motorola6800_parity_and_determinism_gate() {
    assert_eq!(
        family_runtime_mode("motorola6800"),
        FamilyRuntimeMode::Authoritative
    );
    assert!(package_runtime_default_enabled_for_family("motorola6800"));

    let source = [
        "    .cpu m6809",
        "    .org $1000",
        "start:",
        "    LDA #$2A",
        "    LDA ,X+",
        "    BNE start",
        "    LBRA done",
        "done:",
        "    RTS",
    ];

    let native = assemble_source_entries_with_runtime_mode(&source, false)
        .expect("native source assembly should run");
    let runtime_a = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source assembly should run");
    let runtime_b = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source re-run should be deterministic");

    assert_eq!(runtime_a.0, native.0, "bytes/reloc parity mismatch");
    assert_eq!(runtime_a.1, native.1, "diagnostic parity mismatch");
    assert_eq!(
        runtime_b.0, runtime_a.0,
        "runtime bytes are non-deterministic"
    );
    assert_eq!(
        runtime_b.1, runtime_a.1,
        "runtime diagnostics are non-deterministic"
    );
}

#[test]
fn vm_expr_parser_rollout_criteria_all_registered_families_have_policy_and_checklist() {
    let registry = default_registry();
    for family in registry.family_ids() {
        let policy = crate::vm::rollout::family_expr_parser_rollout_policy(family.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "missing expr-parser rollout policy for family '{}'",
                    family.as_str()
                )
            });
        assert!(
            !policy.migration_checklist.trim().is_empty(),
            "missing expr-parser migration checklist for family '{}'",
            family.as_str()
        );
    }
}

#[test]
fn vm_expr_parser_rollout_criteria_mos_intel_and_motorola_default_authoritative() {
    assert!(crate::vm::rollout::portable_expr_parser_runtime_default_enabled_for_family("mos6502"));
    assert!(
        crate::vm::rollout::portable_expr_parser_runtime_default_enabled_for_family("intel8080")
    );
    assert!(
        crate::vm::rollout::portable_expr_parser_runtime_default_enabled_for_family("motorola6800")
    );
}

#[test]
fn vm_expr_eval_rollout_criteria_mos_intel_and_motorola_default_authoritative() {
    assert!(crate::vm::rollout::portable_expr_runtime_default_enabled_for_family("mos6502"));
    assert!(crate::vm::rollout::portable_expr_runtime_default_enabled_for_family("intel8080"));
    assert!(crate::vm::rollout::portable_expr_runtime_default_enabled_for_family("motorola6800"));
}

#[test]
fn vm_runtime_intel8085_path_uses_package_forms() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mvi_a = crate::families::intel8080::table::lookup_instruction("MVI", Some("A"), None)
        .expect("MVI A should exist");
    let mvi_mode_key = mode_key_for_instruction_entry(mvi_a);
    for table in &mut chunks.tables {
        let is_intel_family_owner = matches!(&table.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"));
        if is_intel_family_owner
            && table.mnemonic.eq_ignore_ascii_case("mvi")
            && table.mode_key == mvi_mode_key
        {
            table.program = vec![OP_EMIT_U8, 0x00, OP_EMIT_OPERAND, 0x00, OP_END];
        }
    }
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A,$42", 1, 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x00, 0x42]);
}

#[test]
fn vm_runtime_z80_dialect_path_uses_package_forms() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, z80_cpu_id, &registry);
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mov_a_b =
        crate::families::intel8080::table::lookup_instruction("MOV", Some("A"), Some("B"))
            .expect("MOV A,B should exist");
    let mov_mode_key = mode_key_for_instruction_entry(mov_a_b);
    for table in &mut chunks.tables {
        let is_intel_family_owner = matches!(&table.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"));
        if is_intel_family_owner
            && table.mnemonic.eq_ignore_ascii_case("mov")
            && table.mode_key == mov_mode_key
        {
            table.program = vec![OP_EMIT_U8, 0x00, OP_END];
        }
    }
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LD A,B", 1, 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x00]);
}

#[test]
fn vm_runtime_intel8080_family_rewrite_pairs_match_native_mode() {
    let pairs = [
        ("    MVI A,55h", "    LD A,55h"),
        ("    MOV A,B", "    LD A,B"),
        ("    JMP 1000h", "    JP 1000h"),
        ("    JZ 1000h", "    JP Z,1000h"),
        ("    ADI 10h", "    ADD A,10h"),
    ];

    for (intel_line, z80_line) in pairs {
        let intel_native = assemble_line_with_runtime_mode(i8085_cpu_id, intel_line, false);
        let intel_runtime = assemble_line_with_runtime_mode(i8085_cpu_id, intel_line, true);
        assert_eq!(
            intel_runtime.0, intel_native.0,
            "8085 status mismatch for '{}'",
            intel_line
        );
        assert_eq!(
            intel_runtime.1, intel_native.1,
            "8085 diagnostic mismatch for '{}'",
            intel_line
        );
        assert_eq!(
            intel_runtime.2, intel_native.2,
            "8085 bytes mismatch for '{}'",
            intel_line
        );

        let z80_native = assemble_line_with_runtime_mode(z80_cpu_id, z80_line, false);
        let z80_runtime = assemble_line_with_runtime_mode(z80_cpu_id, z80_line, true);
        assert_eq!(
            z80_runtime.0, z80_native.0,
            "z80 status mismatch for '{}'",
            z80_line
        );
        assert_eq!(
            z80_runtime.1, z80_native.1,
            "z80 diagnostic mismatch for '{}'",
            z80_line
        );
        assert_eq!(
            z80_runtime.2, z80_native.2,
            "z80 bytes mismatch for '{}'",
            z80_line
        );

        assert_eq!(
            intel_runtime.2, z80_runtime.2,
            "intel/z80 rewrite bytes mismatch for pair '{}'<->'{}'",
            intel_line, z80_line
        );
    }
}

#[test]
fn vm_runtime_intel8085_extension_parity_corpus_matches_native_mode() {
    let corpus = ["    RIM", "    SIM"];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(i8085_cpu_id, line, false);
        let runtime = assemble_line_with_runtime_mode(i8085_cpu_id, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_z80_extension_parity_corpus_matches_native_mode() {
    let corpus = ["    DJNZ $0004", "    RLC B"];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(z80_cpu_id, line, false);
        let runtime = assemble_line_with_runtime_mode(z80_cpu_id, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_mos6502_missing_tabl_program_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.tables.retain(|program| {
        let is_mos6502_owner =
            matches!(&program.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        !(is_mos6502_owner
            && program.mnemonic.eq_ignore_ascii_case("lda")
            && program.mode_key.eq_ignore_ascii_case("immediate"))
    });
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message.to_ascii_lowercase().contains("missing vm program"));
}

#[test]
fn vm_runtime_mos6502_parser_vm_failure_errors_instead_of_host_parser_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .parser_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family parser vm program");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.program = vec![ParserVmOpcode::Fail as u8, ParserVmOpcode::End as u8];
    chunks.parser_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message
            .to_ascii_lowercase()
            .contains("parser vm requested failure"),
        "expected parser VM failure diagnostics, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_expression_contract_breakage_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .parser_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family parser contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.grammar_id = "opforge.line.v0".to_string();
    chunks.parser_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message
            .to_ascii_lowercase()
            .contains("unsupported parser grammar id"),
        "expected expression contract compatibility diagnostic, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_expr_parser_contract_breakage_errors_instead_of_host_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_parser_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr parser contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.opcode_version = EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.expr_parser_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #($10 + 1)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message
            .to_ascii_lowercase()
            .contains("unsupported expression parser contract opcode version"),
        "expected expression parser contract compatibility failure, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_data_eval_survives_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .byte 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[3]);
}

#[test]
fn vm_runtime_i8085_data_eval_survives_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .byte 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[3]);
}

#[test]
fn vm_runtime_mos6502_expr_parse_survives_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_core_expr_parser_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_core_expr_parser_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .byte 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[3]);
}

#[test]
fn vm_runtime_i8085_expr_parse_survives_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_core_expr_parser_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_core_expr_parser_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .byte 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[3]);
}

#[test]
fn vm_runtime_mos6502_instruction_expr_parse_survives_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_core_expr_parser_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_core_expr_parser_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #(1+2)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[0xA9, 0x03]);
}

#[test]
fn vm_runtime_i8085_instruction_expr_parse_survives_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_core_expr_parser_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_core_expr_parser_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A, 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[0x3E, 0x03]);
}

#[test]
fn vm_runtime_mos6502_instruction_expr_eval_survives_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #(1+2)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[0xA9, 0x03]);
}

#[test]
fn vm_runtime_i8085_instruction_expr_eval_survives_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A, 1+2", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Ok, "unexpected error: {message}");
    assert_eq!(asm.bytes(), &[0x3E, 0x03]);
}

#[test]
fn vm_runtime_intel8085_expr_parser_contract_breakage_errors_instead_of_host_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_parser_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr parser contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.opcode_version = EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.expr_parser_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A, ($10 + 1)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message
            .to_ascii_lowercase()
            .contains("unsupported expression parser contract opcode version"),
        "expected expression parser contract compatibility failure, got: {message}"
    );
}

#[test]
fn vm_runtime_motorola6800_expr_parser_contract_breakage_errors_instead_of_host_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_parser_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("motorola6800"))
        })
        .cloned()
        .expect("motorola6800 family expr parser contract");
    cpu_override.owner = ScopedOwner::Cpu("m6809".to_string());
    cpu_override.opcode_version = EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.expr_parser_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #($10 + 1)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message
            .to_ascii_lowercase()
            .contains("unsupported expression parser contract opcode version"),
        "expected expression parser contract compatibility failure, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_eval_expr_uses_expr_contract_budgets() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));

    let span = crate::core::tokenizer::Span::default();
    let expr = crate::core::parser::Expr::Binary {
        op: crate::core::parser::BinaryOp::Add,
        left: Box::new(crate::core::parser::Expr::Number("1".to_string(), span)),
        right: Box::new(crate::core::parser::Expr::Number("2".to_string(), span)),
        span,
    };

    let err = crate::core::family::AssemblerContext::eval_expr(&asm, &expr)
        .expect_err("portable eval should enforce expr contract budget");
    assert!(err.to_ascii_lowercase().contains("ope007"));
}

#[test]
fn vm_runtime_mos6502_eval_expr_uses_portable_eval_by_default_when_certified() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #3", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected default certified VM eval path to enforce expr budgets, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_eval_expr_force_host_override_disables_default_vm() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.opthread_expr_eval_force_host_families
        .push("mos6502".to_string());
    asm.opthread_expr_eval_force_host_families
        .push("m6502".to_string());
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #3", 1, 0, 2);
    assert_eq!(status, LineStatus::Ok);
}

#[test]
fn vm_runtime_mos6502_data_directive_eval_uses_portable_eval_by_default_when_certified() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .byte ($10 + 1)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected certified data directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_intel8085_data_directive_eval_uses_portable_eval_by_default() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    .db (1 + 2)", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected intel8080-family data directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_layout_directive_eval_uses_portable_eval_by_default_when_certified() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process(".region ram, $1000, $10ff, align=(1+1)", 1, 0, 1);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected certified layout directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_intel8085_layout_directive_eval_uses_portable_eval_by_default() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process(".region ram, $1000, $10ff, align=(1+1)", 1, 0, 1);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected intel8080-family layout directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_complex_layout_directives_survive_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let lines = vec![
        ".module main".to_string(),
        ".cpu 6502".to_string(),
        ".section code, align=(1+1)".to_string(),
        "    .byte $aa".to_string(),
        ".endsection".to_string(),
        ".section data, align=(1+1)".to_string(),
        "    .byte $bb".to_string(),
        ".endsection".to_string(),
        ".region ram, $1000, $10ff, align=(1+1)".to_string(),
        ".pack in ram : code, data".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();

    let pass1 = assembler.pass1(&lines);
    assert_eq!(
        pass1.errors,
        0,
        "expected certified complex layout directives to bypass host evaluator failpoint: {:?}",
        assembler
            .diagnostics
            .iter()
            .map(|diag| format!("{}:{}", diag.line, diag.error.message()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn vm_runtime_i8085_complex_layout_directives_survive_host_evaluator_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            set_host_expr_eval_failpoint_for_tests(false);
        }
    }

    let _reset = FailpointReset;
    set_host_expr_eval_failpoint_for_tests(true);

    let lines = vec![
        ".module main".to_string(),
        ".cpu 8085".to_string(),
        ".section code, align=(1+1)".to_string(),
        "    .db 1".to_string(),
        ".endsection".to_string(),
        ".section data, align=(1+1)".to_string(),
        "    .db 2".to_string(),
        ".endsection".to_string(),
        ".region ram, $1000, $10ff, align=(1+1)".to_string(),
        ".pack in ram : code, data".to_string(),
        ".endmodule".to_string(),
    ];

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("main".to_string());
    assembler.clear_diagnostics();

    let pass1 = assembler.pass1(&lines);
    assert_eq!(
        pass1.errors,
        0,
        "expected intel8080-family complex layout directives to bypass host evaluator failpoint: {:?}",
        assembler
            .diagnostics
            .iter()
            .map(|diag| format!("{}:{}", diag.line, diag.error.message()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn vm_runtime_mos6502_output_directive_eval_uses_portable_eval_by_default_when_certified() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    assert_eq!(asm.process(".module main", 1, 0, 1), LineStatus::Ok);
    let status = asm.process(
        ".output \"out.bin\", format=bin, sections=code, image=\"$1000..$1001\", fill=(1+2)",
        2,
        0,
        1,
    );
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected certified output directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_intel8085_output_directive_eval_uses_portable_eval_by_default() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    assert_eq!(asm.process(".module main", 1, 0, 1), LineStatus::Ok);
    let status = asm.process(
        ".output \"out.bin\", format=bin, sections=code, image=\"$1000..$1001\", fill=(1+2)",
        2,
        0,
        1,
    );
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected intel8080-family output directive expression to enforce VM budget contract, got: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_selector_unknown_symbol_uses_explicit_compat_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let chunks = build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA missing_label", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("label not found"),
        "expected host compatibility diagnostic shape, got: {message}"
    );
    assert!(
        !message.to_ascii_lowercase().contains("ope004"),
        "unexpected direct VM unknown-symbol diagnostic leaked instead of compat fallback: {message}"
    );
}

#[test]
fn vm_runtime_mos6502_selector_non_compat_eval_error_does_not_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA $10 + 1", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected non-compat VM evaluation error without host fallback, got: {message}"
    );
}

#[test]
fn vm_runtime_intel8085_unresolved_and_unstable_symbol_parity_native_vs_portable_eval() {
    let unresolved_native =
        assemble_i8085_line_with_expr_vm_opt_in("    MVI A, missing_symbol", 0x1000, None, false);
    let unresolved_runtime =
        assemble_i8085_line_with_expr_vm_opt_in("    MVI A, missing_symbol", 0x1000, None, true);
    assert_eq!(unresolved_runtime.0, unresolved_native.0);
    assert_eq!(unresolved_runtime.1, unresolved_native.1);
    assert_eq!(unresolved_runtime.2, unresolved_native.2);

    let unstable_native = assemble_i8085_line_with_expr_vm_opt_in(
        "    MVI A, target",
        0x1000,
        Some((0x0010, false)),
        false,
    );
    let unstable_runtime = assemble_i8085_line_with_expr_vm_opt_in(
        "    MVI A, target",
        0x1000,
        Some((0x0010, false)),
        true,
    );
    assert_eq!(unstable_runtime.0, unstable_native.0);
    assert_eq!(unstable_runtime.1, unstable_native.1);
    assert_eq!(unstable_runtime.2, unstable_native.2);

    let finalized_native = assemble_i8085_line_with_expr_vm_opt_in(
        "    MVI A, target",
        0x1000,
        Some((0x0010, true)),
        false,
    );
    let finalized_runtime = assemble_i8085_line_with_expr_vm_opt_in(
        "    MVI A, target",
        0x1000,
        Some((0x0010, true)),
        true,
    );
    assert_eq!(finalized_runtime.0, finalized_native.0);
    assert_eq!(finalized_runtime.1, finalized_native.1);
    assert_eq!(finalized_runtime.2, finalized_native.2);
}

#[test]
fn vm_runtime_motorola6800_unresolved_and_unstable_symbol_parity_native_vs_portable_eval() {
    for cpu in [m6809_cpu_id, hd6309_cpu_id] {
        let unresolved_native = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #missing_symbol",
            0x1000,
            None,
            true,
        );
        let unresolved_runtime = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #missing_symbol",
            0x1000,
            None,
            false,
        );
        assert_eq!(unresolved_runtime.0, unresolved_native.0);
        assert_eq!(unresolved_runtime.1, unresolved_native.1);
        assert_eq!(unresolved_runtime.2, unresolved_native.2);

        let unstable_native = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #target",
            0x1000,
            Some((0x002A, false)),
            true,
        );
        let unstable_runtime = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #target",
            0x1000,
            Some((0x002A, false)),
            false,
        );
        assert_eq!(unstable_runtime.0, unstable_native.0);
        assert_eq!(unstable_runtime.1, unstable_native.1);
        assert_eq!(unstable_runtime.2, unstable_native.2);

        let finalized_native = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #target",
            0x1000,
            Some((0x002A, true)),
            true,
        );
        let finalized_runtime = assemble_line_with_expr_vm_force_host(
            cpu,
            "motorola6800",
            "    LDA #target",
            0x1000,
            Some((0x002A, true)),
            false,
        );
        assert_eq!(finalized_runtime.0, finalized_native.0);
        assert_eq!(finalized_runtime.1, finalized_native.1);
        assert_eq!(finalized_runtime.2, finalized_native.2);
    }
}

#[test]
fn vm_runtime_intel8085_ternary_precedence_and_dollar_parity_native_vs_portable_eval() {
    let corpus = [
        "    MVI A, ((1 + 2 * 3) == 7 ? $2A : $55)",
        "    MVI A, (($ + 2) > $1000 ? $11 : $22)",
        "    MVI A, ((<$1234) + ($80 >> 3))",
    ];

    for line in corpus {
        let native = assemble_i8085_line_with_expr_vm_opt_in(line, 0x1000, None, false);
        let runtime_a = assemble_i8085_line_with_expr_vm_opt_in(line, 0x1000, None, true);
        let runtime_b = assemble_i8085_line_with_expr_vm_opt_in(line, 0x1000, None, true);

        assert_eq!(runtime_a.0, native.0, "status mismatch for '{line}'");
        assert_eq!(runtime_a.1, native.1, "diagnostic mismatch for '{line}'");
        assert_eq!(runtime_a.2, native.2, "byte mismatch for '{line}'");

        assert_eq!(runtime_b.0, runtime_a.0, "runtime status non-deterministic");
        assert_eq!(
            runtime_b.1, runtime_a.1,
            "runtime diagnostics non-deterministic"
        );
        assert_eq!(runtime_b.2, runtime_a.2, "runtime bytes non-deterministic");
    }
}

#[test]
fn vm_runtime_motorola6800_ternary_precedence_and_dollar_parity_native_vs_portable_eval() {
    let corpus = [
        "    LDA #((1 + 2 * 3) == 7 ? $2A : $55)",
        "    LDA #(($ + 2) > $1000 ? $11 : $22)",
        "    LDA #((<$1234) + ($80 >> 3))",
    ];

    for cpu in [m6809_cpu_id, hd6309_cpu_id] {
        for line in corpus {
            let native = assemble_line_with_expr_vm_force_host(
                cpu,
                "motorola6800",
                line,
                0x1000,
                None,
                true,
            );
            let runtime_a = assemble_line_with_expr_vm_force_host(
                cpu,
                "motorola6800",
                line,
                0x1000,
                None,
                false,
            );
            let runtime_b = assemble_line_with_expr_vm_force_host(
                cpu,
                "motorola6800",
                line,
                0x1000,
                None,
                false,
            );

            assert_eq!(
                runtime_a.0,
                native.0,
                "status mismatch for '{}' on {}",
                line,
                cpu.as_str()
            );
            assert_eq!(
                runtime_a.1,
                native.1,
                "diagnostic mismatch for '{}' on {}",
                line,
                cpu.as_str()
            );
            assert_eq!(
                runtime_a.2,
                native.2,
                "byte mismatch for '{}' on {}",
                line,
                cpu.as_str()
            );

            assert_eq!(runtime_b.0, runtime_a.0, "runtime status non-deterministic");
            assert_eq!(
                runtime_b.1, runtime_a.1,
                "runtime diagnostics non-deterministic"
            );
            assert_eq!(runtime_b.2, runtime_a.2, "runtime bytes non-deterministic");
        }
    }
}

#[test]
fn vm_runtime_intel8085_eval_expr_uses_portable_eval_by_default_when_authoritative() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A, 3", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected default intel8080-family VM eval path to enforce expr budgets, got: {message}"
    );
}

#[test]
fn vm_runtime_motorola6800_eval_expr_uses_portable_eval_by_default_when_authoritative() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6809_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("motorola6800"))
        })
        .cloned()
        .expect("motorola6800 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("m6809".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #3", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(
        message.to_ascii_lowercase().contains("ope007"),
        "expected default motorola6800-family VM eval path to enforce expr budgets, got: {message}"
    );
}

#[test]
fn vm_runtime_intel8085_eval_expr_uses_portable_eval_when_opted_in() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, i8085_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .expr_contracts
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family expr contract");
    cpu_override.owner = ScopedOwner::Cpu("8085".to_string());
    cpu_override.max_eval_steps = 0;
    chunks.expr_contracts.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.opthread_expr_eval_opt_in_families
        .push("intel8080".to_string());
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    MVI A, 3", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message.to_ascii_lowercase().contains("ope007"));
}

#[test]
fn vm_runtime_mos6502_missing_tokenizer_vm_program_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("produced no tokens for non-empty source line"));
}

#[test]
fn vm_runtime_mos6502_invalid_tokenizer_vm_opcode_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.program = vec![0xFE];
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("unknown tokenizer vm opcode"));
}

#[test]
fn vm_runtime_mos6502_delegate_tokenizer_vm_opcode_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.program = vec![
        TokenizerVmOpcode::DelegateCore as u8,
        TokenizerVmOpcode::End as u8,
    ];
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("delegatecore opcode is forbidden"));
}

#[test]
fn vm_runtime_mos6502_malformed_tokenizer_vm_state_table_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"))
        })
        .cloned()
        .expect("mos6502 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("m6502".to_string());
    cpu_override.state_entry_offsets = Vec::new();
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA #$10", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("tokenizer vm state table is empty"));
}

#[test]
fn vm_runtime_intel8080_family_tokenization_requires_vm_tokens_when_authoritative() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, z80_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("z80".to_string());
    cpu_override.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LD A,B", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("produced no tokens for non-empty source line"));
}

#[test]
fn vm_runtime_intel8080_family_tokenization_is_vm_strict_even_when_runtime_flag_is_off() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, z80_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_override = chunks
        .tokenizer_vm_programs
        .iter()
        .find(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("intel8080"))
        })
        .cloned()
        .expect("intel8080 family tokenizer vm program");
    cpu_override.owner = ScopedOwner::Cpu("z80".to_string());
    cpu_override.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(cpu_override);

    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LD A,B", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .to_ascii_lowercase()
        .contains("produced no tokens for non-empty source line"));
}

#[test]
fn vm_runtime_m6502_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.selectors.retain(|selector| {
        let owner_is_mos6502_family =
            matches!(&selector.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        !(selector.mnemonic.eq_ignore_ascii_case("lda")
            && selector.shape_key.eq_ignore_ascii_case("direct")
            && owner_is_mos6502_family)
    });
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA $1234", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message.contains("No instruction found for LDA"));
}

#[test]
fn vm_runtime_m65c02_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m65c02_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.selectors.retain(|selector| {
        let owner_is_mos6502_family =
            matches!(&selector.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        !(selector.mnemonic.eq_ignore_ascii_case("lda")
            && selector.shape_key.eq_ignore_ascii_case("direct")
            && owner_is_mos6502_family)
    });
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA $1234", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message.contains("No instruction found for LDA"));
}

#[test]
fn vm_runtime_m65816_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu(&mut symbols, m65816_cpu_id, &registry);

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.selectors.retain(|selector| {
        let owner_is_mos6502_family =
            matches!(&selector.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        let owner_is_m65816_cpu =
            matches!(&selector.owner, ScopedOwner::Cpu(owner) if owner.eq_ignore_ascii_case("65816"));
        !(selector.mnemonic.eq_ignore_ascii_case("lda")
            && selector.shape_key.eq_ignore_ascii_case("direct")
            && (owner_is_mos6502_family || owner_is_m65816_cpu))
    });
    asm.opthread_execution_model =
        Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
    asm.clear_conditionals();
    asm.clear_scopes();

    let status = asm.process("    LDA $1234", 1, 0, 2);
    let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
    assert_eq!(status, LineStatus::Error);
    assert!(message.contains("No instruction found for LDA"));
}

#[test]
fn vm_runtime_mos6502_parity_corpus_matches_native_mode() {
    let corpus = [
        "    LDA #$10",
        "    STA $2000",
        "    ADC ($10),Y",
        "    JMP $1234",
        "    BNE $0004",
        "    BRA $0004",
        "    JMP missing_label",
    ];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(m6502_cpu_id, line, false);
        let package_mode = assemble_line_with_runtime_mode(m6502_cpu_id, line, true);
        assert_eq!(package_mode.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(
            package_mode.1, native.1,
            "diagnostic mismatch for '{}'",
            line
        );
        assert_eq!(package_mode.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_vm_eval_enabled_families_parity_corpus_matches_native_mode() {
    // VM-eval-enabled families should keep byte+diagnostic parity with host mode.
    // Verify representative family CPUs keep byte+diagnostic parity with host mode.
    let corpus = [
        (m6502_cpu_id, "    LDA #$10"),
        (m65c02_cpu_id, "    BRA $0004"),
        (m65816_cpu_id, "    LDA $123456,k"),
        (m65816_cpu_id, "    JMP $1234"),
        (m6809_cpu_id, "    LDA #((1 + 2) * 3)"),
        (hd6309_cpu_id, "    LDA #((1 + 2) * 3)"),
    ];

    for (cpu, line) in corpus {
        let native = assemble_line_with_runtime_mode(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode(cpu, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_parser_tokenizer_parity_corpus_matches_native_mode() {
    let corpus = [
        (m6502_cpu_id, "LABEL: LDA #$10 ; trailing comment"),
        (m6502_cpu_id, "LABEL LDA $10,X"),
        (m6502_cpu_id, "    ASL A"),
        (m6502_cpu_id, "    .byte \"A\", $42, %1010"),
        (m6502_cpu_id, "    .word >$1234, <$1234"),
        (m6502_cpu_id, "1mov a,b"),
        (m65c02_cpu_id, "    ASL A"),
        (m65c02_cpu_id, "    BRA $0004"),
        (m65816_cpu_id, "    LDA [$10],Y"),
        (m65816_cpu_id, "    LDA $123456,l"),
        (m6809_cpu_id, "LABEL: LDA #$10 ; trailing comment"),
        (m6809_cpu_id, "    LDA ,X++"),
        (m6809_cpu_id, "    LDA [$20,X]"),
        (m6809_cpu_id, "    PSHS A,B,CC"),
        (m6809_cpu_id, "    TFR A,B"),
        (m6809_cpu_id, "    LBRA $0004"),
        (hd6309_cpu_id, "    SEXW"),
        (hd6309_cpu_id, "    CLRD"),
    ];

    for (cpu, line) in corpus {
        let native = assemble_line_with_runtime_mode(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode(cpu, line, true);
        assert_eq!(
            runtime.0,
            native.0,
            "status mismatch for '{}' on {}",
            line,
            cpu.as_str()
        );
        assert_eq!(
            runtime.1,
            native.1,
            "diagnostic mismatch for '{}' on {}",
            line,
            cpu.as_str()
        );
        assert_eq!(
            runtime.2,
            native.2,
            "bytes mismatch for '{}' on {}",
            line,
            cpu.as_str()
        );
    }
}

#[test]
fn vm_runtime_mos6502_expr_resolver_rejects_unsupported_shape_without_fallback() {
    let line = "    LDA ($10,S),Y";
    let native = assemble_line_with_runtime_mode(m6502_cpu_id, line, false);
    let runtime = assemble_line_with_runtime_mode(m6502_cpu_id, line, true);
    assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
    assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
    assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
}

#[test]
fn vm_runtime_non_65816_force_suffix_diagnostics_match_native_mode() {
    let corpus = [
        (m6502_cpu_id, "    LDA $10,d"),
        (m65c02_cpu_id, "    LDA $10,d"),
    ];

    for (cpu, line) in corpus {
        let native = assemble_line_with_runtime_mode(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode(cpu, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_mos6502_pathological_line_corpus_matches_native_mode() {
    let corpus = [
        (m6502_cpu_id, "    LDA missing_label"),
        (m6502_cpu_id, "    BNE missing_label"),
        (m65c02_cpu_id, "    LDA missing_label"),
        (m65c02_cpu_id, "    LDA $10,d"),
        (m65816_cpu_id, "    LDA $123456,k"),
        (m65816_cpu_id, "    JMP $123456,b"),
    ];

    for (cpu, line) in corpus {
        let native = assemble_line_with_runtime_mode(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode(cpu, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_m65816_width_edge_program_matches_native_mode() {
    let source = [
        "    .cpu 65816",
        "    SEP #$20",
        "    LDA #$1234",
        "    REP #$20",
        "    LDA #$1234",
    ];

    let native = assemble_source_entries_with_runtime_mode(&source, false)
        .expect("native source assembly should run");
    let runtime = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source assembly should run");
    assert_eq!(runtime.0, native.0, "image parity mismatch");
    assert_eq!(runtime.1, native.1, "diagnostic parity mismatch");
}

#[test]
fn vm_runtime_mos6502_selector_conflict_reports_deterministic_error() {
    let registry = default_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.selectors.retain(|selector| {
        let owner_is_mos6502_family =
            matches!(&selector.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        !(selector.mnemonic.eq_ignore_ascii_case("lda")
            && selector.shape_key.eq_ignore_ascii_case("direct")
            && owner_is_mos6502_family)
    });
    chunks.selectors.push(ModeSelectorDescriptor {
        owner: ScopedOwner::Family("mos6502".to_string()),
        mnemonic: "lda".to_string(),
        shape_key: "direct".to_string(),
        mode_key: "absolute".to_string(),
        operand_plan: "u8".to_string(),
        priority: 0,
        unstable_widen: false,
        width_rank: 1,
    });

    let (status_a, message_a) = {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
        asm.opthread_execution_model = Some(
            HierarchyExecutionModel::from_chunks(chunks.clone()).expect("execution model build"),
        );
        asm.clear_conditionals();
        asm.clear_scopes();
        let status = asm.process("    LDA $1234", 1, 0, 2);
        let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
        (status, message)
    };

    let (status_b, message_b) = {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::with_cpu(&mut symbols, m6502_cpu_id, &registry);
        asm.opthread_execution_model =
            Some(HierarchyExecutionModel::from_chunks(chunks).expect("execution model build"));
        asm.clear_conditionals();
        asm.clear_scopes();
        let status = asm.process("    LDA $1234", 1, 0, 2);
        let message = asm.error().map(|err| err.to_string()).unwrap_or_default();
        (status, message)
    };

    assert_eq!(status_a, LineStatus::Error);
    assert_eq!(status_b, LineStatus::Error);
    assert!(!message_a.is_empty());
    assert_eq!(message_a, message_b);
}

#[test]
fn vm_runtime_mos6502_example_programs_match_native_mode() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let corpus = ["6502_simple.asm", "6502_allmodes.asm", "mos6502_modes.asm"];

    for name in corpus {
        let path = base.join(name);
        let native = assemble_example_entries_with_runtime_mode(&path, false)
            .expect("native example assembly should run");
        let runtime = assemble_example_entries_with_runtime_mode(&path, true)
            .expect("runtime example assembly should run");
        assert_eq!(runtime.0, native.0, "image parity mismatch for {}", name);
        assert_eq!(
            runtime.1, native.1,
            "diagnostic parity mismatch for {}",
            name
        );
    }
}

#[test]
fn vm_runtime_mos6502_relocation_heavy_program_matches_native_mode() {
    let source = [
        "    .cpu 6502",
        "    .org $1000",
        "start:",
        "    LDA #<target",
        "    STA ptr",
        "    LDA #>target",
        "    STA ptr+1",
        "    BNE later",
        "ptr: .word target",
        "    .byte $EA,$EA,$EA",
        "later:",
        "    BEQ start",
        "target:",
        "    LDA #$42",
        "    RTS",
    ];

    let native = assemble_source_entries_with_runtime_mode(&source, false)
        .expect("native source assembly should run");
    let runtime = assemble_source_entries_with_runtime_mode(&source, true)
        .expect("runtime source assembly should run");
    assert_eq!(runtime.0, native.0, "image parity mismatch");
    assert_eq!(runtime.1, native.1, "diagnostic parity mismatch");
}

#[test]
fn vm_runtime_m65c02_example_programs_match_native_mode() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let corpus = ["65c02_simple.asm", "65c02_allmodes.asm"];

    for name in corpus {
        let path = base.join(name);
        let native = assemble_example_entries_with_runtime_mode(&path, false)
            .expect("native example assembly should run");
        let runtime = assemble_example_entries_with_runtime_mode(&path, true)
            .expect("runtime example assembly should run");
        assert_eq!(runtime.0, native.0, "image parity mismatch for {}", name);
        assert_eq!(
            runtime.1, native.1,
            "diagnostic parity mismatch for {}",
            name
        );
    }
}

#[test]
fn vm_runtime_m65816_example_programs_match_native_mode() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let corpus = [
        "65816_simple.asm",
        "65816_allmodes.asm",
        "65816_assume_state.asm",
        "65816_wide_alignment.asm",
        "65816_wide_const_var.asm",
        "65816_wide_image.asm",
        "65816_wide_listing_aux.asm",
        "65816_wide_mapfile.asm",
        "65816_bss_wide_reserve.asm",
    ];

    for name in corpus {
        let path = base.join(name);
        let native = assemble_example_entries_with_runtime_mode(&path, false)
            .expect("native example assembly should run");
        let runtime = assemble_example_entries_with_runtime_mode(&path, true)
            .expect("runtime example assembly should run");
        assert_eq!(runtime.0, native.0, "image parity mismatch for {}", name);
        assert_eq!(
            runtime.1, native.1,
            "diagnostic parity mismatch for {}",
            name
        );
    }
}

#[test]
fn vm_runtime_mos_family_diagnostic_boundary_parity_matches_native_mode() {
    let corpus = [
        (m6502_cpu_id, "    BNE $0200"),
        (m6502_cpu_id, "    JMP missing_label"),
        (m65c02_cpu_id, "    BBR0 $12,$0200"),
        (m65816_cpu_id, "    BRL $8003"),
        (m65816_cpu_id, "    LDA $123456,k"),
        (m65816_cpu_id, "    JMP $123456,b"),
    ];

    for (cpu, line) in corpus {
        let native = assemble_line_with_runtime_mode(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode(cpu, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_m65c02_extension_parity_corpus_matches_native_mode() {
    let corpus = [
        "    BRA $0004",
        "    BBR0 $12,$0005",
        "    STZ $10",
        "    BIT #$10",
        "    JMP ($1234,X)",
        "    SMB0 $10",
    ];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(m65c02_cpu_id, line, false);
        let package_mode = assemble_line_with_runtime_mode(m65c02_cpu_id, line, true);
        assert_eq!(package_mode.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(
            package_mode.1, native.1,
            "diagnostic mismatch for '{}'",
            line
        );
        assert_eq!(package_mode.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_m65816_extension_parity_corpus_matches_native_mode() {
    let corpus = [
        "    REP #$30",
        "    SEP #$20",
        "    XBA",
        "    JSL $001234",
        "    JML $001234",
        "    MVN $01,$02",
        "    LDA $123456",
        "    LDA $123456,X",
        "    LDA $123456,l",
        "    LDA $1234,b",
        "    JMP $1234,k",
        "    LDA $f0,d",
    ];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(m65816_cpu_id, line, false);
        let package_mode = assemble_line_with_runtime_mode(m65816_cpu_id, line, true);
        assert_eq!(package_mode.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(
            package_mode.1, native.1,
            "diagnostic mismatch for '{}'",
            line
        );
        assert_eq!(package_mode.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[test]
fn vm_runtime_m65c02_table_modes_match_native_mode() {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();

    for entry in FAMILY_INSTRUCTION_TABLE {
        let key = format!("{}:{:?}", entry.mnemonic, entry.mode);
        if !seen.insert(key.clone()) {
            continue;
        }
        let line = match mos6502_operand_for_mode(entry.mode) {
            Some(operand) => format!("    {} {}", entry.mnemonic, operand),
            None => format!("    {}", entry.mnemonic),
        };
        cases.push((key, line));
    }
    for entry in M65C02_INSTRUCTION_TABLE {
        if entry.mnemonic.starts_with("BBR") || entry.mnemonic.starts_with("BBS") {
            // Bit-branch mnemonics require two operands; keep this parity corpus
            // focused on one-operand mode table entries.
            continue;
        }
        let key = format!("{}:{:?}", entry.mnemonic, entry.mode);
        if !seen.insert(key.clone()) {
            continue;
        }
        let line = match mos6502_operand_for_mode(entry.mode) {
            Some(operand) => format!("    {} {}", entry.mnemonic, operand),
            None => format!("    {}", entry.mnemonic),
        };
        cases.push((key, line));
    }

    for (case_id, line) in cases {
        let native = assemble_line_with_runtime_mode(m65c02_cpu_id, &line, false);
        let runtime = assemble_line_with_runtime_mode(m65c02_cpu_id, &line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for {}", case_id);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for {}", case_id);
        assert_eq!(runtime.2, native.2, "bytes mismatch for {}", case_id);
    }
}

#[test]
fn vm_runtime_m65816_table_modes_match_native_mode() {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();

    for entry in FAMILY_INSTRUCTION_TABLE {
        let key = format!("{}:{:?}", entry.mnemonic, entry.mode);
        if !seen.insert(key.clone()) {
            continue;
        }
        let line = match mos6502_operand_for_mode(entry.mode) {
            Some(operand) => format!("    {} {}", entry.mnemonic, operand),
            None => format!("    {}", entry.mnemonic),
        };
        cases.push((key, line));
    }
    for entry in M65816_INSTRUCTION_TABLE {
        let key = format!("{}:{:?}", entry.mnemonic, entry.mode);
        if !seen.insert(key.clone()) {
            continue;
        }
        let line = match mos6502_operand_for_mode(entry.mode) {
            Some(operand) => format!("    {} {}", entry.mnemonic, operand),
            None => format!("    {}", entry.mnemonic),
        };
        cases.push((key, line));
    }

    for (case_id, line) in cases {
        let native = assemble_line_with_runtime_mode(m65816_cpu_id, &line, false);
        let runtime = assemble_line_with_runtime_mode(m65816_cpu_id, &line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for {}", case_id);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for {}", case_id);
        assert_eq!(runtime.2, native.2, "bytes mismatch for {}", case_id);
    }
}

fn mos6502_operand_for_mode(mode: AddressMode) -> Option<&'static str> {
    match mode {
        AddressMode::Implied => None,
        AddressMode::Accumulator => Some("A"),
        AddressMode::Immediate => Some("#$10"),
        AddressMode::ZeroPage => Some("$10"),
        AddressMode::ZeroPageX => Some("$10,X"),
        AddressMode::ZeroPageY => Some("$10,Y"),
        AddressMode::Absolute => Some("$1234"),
        AddressMode::AbsoluteX => Some("$1234,X"),
        AddressMode::AbsoluteY => Some("$1234,Y"),
        AddressMode::Indirect => Some("($1234)"),
        AddressMode::IndexedIndirectX => Some("($10,X)"),
        AddressMode::IndirectIndexedY => Some("($10),Y"),
        AddressMode::IndirectIndexedZ => Some("($10),Z"),
        AddressMode::Relative => Some("$0004"),
        AddressMode::RelativeLong => Some("$0004"),
        AddressMode::ZeroPageIndirect => Some("($10)"),
        AddressMode::AbsoluteIndexedIndirect => Some("($1234,X)"),
        AddressMode::StackRelative => Some("$10,S"),
        AddressMode::StackRelativeIndirectIndexedY => Some("($10,S),Y"),
        AddressMode::AbsoluteLong => Some("$001234"),
        AddressMode::AbsoluteLongX => Some("$001234,X"),
        AddressMode::IndirectLong => Some("[$1234]"),
        AddressMode::DirectPageIndirectLongY => Some("[$10],Y"),
        AddressMode::DirectPageIndirectLongZ => Some("[$10],Z"),
        AddressMode::DirectPageIndirectLong => Some("[$10]"),
        AddressMode::BlockMove => Some("$01,$02"),
    }
}

fn collect_mos6502_native_baseline_snapshot() -> String {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();
    for entry in FAMILY_INSTRUCTION_TABLE {
        let key = format!("{}:{:?}", entry.mnemonic, entry.mode);
        if !seen.insert(key.clone()) {
            continue;
        }
        let source = match mos6502_operand_for_mode(entry.mode) {
            Some(operand) => format!("    {} {}", entry.mnemonic, operand),
            None => format!("    {}", entry.mnemonic),
        };
        cases.push((key, source));
    }

    // Include explicit compatibility/error anchors.
    cases.push(("M6502_ERROR:BRA".to_string(), "    BRA $0004".to_string()));
    cases.push((
        "M6502_ERROR:UNRESOLVED".to_string(),
        "    JMP missing_label".to_string(),
    ));

    cases.sort();

    let mut rows = Vec::with_capacity(cases.len());
    for (case_id, line) in cases {
        let (status, message) = assemble_line_status(m6502_cpu_id, &line);
        let status_name = match status {
            LineStatus::Ok => "ok",
            LineStatus::Error => "error",
            other => panic!("unexpected status {:?} for '{}'", other, line),
        };
        let bytes = if status == LineStatus::Ok {
            assemble_bytes(m6502_cpu_id, &line)
                .into_iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            String::new()
        };
        let diag = message.unwrap_or_default().replace(['\t', '\n'], " ");
        rows.push(format!("{case_id}\t{line}\t{status_name}\t{bytes}\t{diag}"));
    }

    rows.join("\n") + "\n"
}

fn collect_m45gs02_vm_baseline_snapshot() -> String {
    let mut cases = vec![
        ("M45GS02_VM:MAP".to_string(), "    MAP".to_string()),
        (
            "M45GS02_VM:Q_PREFIX_ADCQ_IMM".to_string(),
            "    ADCQ #$10".to_string(),
        ),
        (
            "M45GS02_VM:FLAT_Z_LDA".to_string(),
            "    LDA ($10),Z".to_string(),
        ),
        (
            "M45GS02_VM:RELFAR_BSR_OK".to_string(),
            "    BSR $0004".to_string(),
        ),
        (
            "M45GS02_VM:RELFAR_BSR_RANGE_ERR".to_string(),
            "    BSR $9000".to_string(),
        ),
    ];

    cases.sort();

    let mut rows = Vec::with_capacity(cases.len());
    for (case_id, line) in cases {
        let native = assemble_line_with_runtime_mode_no_injection(m45gs02_cpu_id, &line, false);
        let runtime = assemble_line_with_runtime_mode_no_injection(m45gs02_cpu_id, &line, true);

        assert!(
            runtime.3,
            "45GS02 family should initialize VM model for VM baseline case {}",
            case_id
        );
        assert_eq!(runtime.0, native.0, "status mismatch for {}", case_id);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for {}", case_id);
        assert_eq!(runtime.2, native.2, "bytes mismatch for {}", case_id);

        let status_name = match runtime.0 {
            LineStatus::Ok => "ok",
            LineStatus::Error => "error",
            other => panic!("unexpected status {:?} for '{}'", other, line),
        };
        let bytes = if runtime.0 == LineStatus::Ok {
            runtime
                .2
                .into_iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            String::new()
        };
        let diag = runtime.1.unwrap_or_default().replace(['\t', '\n'], " ");
        rows.push(format!("{case_id}\t{line}\t{status_name}\t{bytes}\t{diag}"));
    }

    rows.join("\n") + "\n"
}

#[test]
fn mos6502_native_baseline_matches_reference() {
    let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vm/reference/mos6502_native_baseline.tsv");
    let snapshot = collect_mos6502_native_baseline_snapshot();

    if std::env::var("opForge_UPDATE_VM_BASELINE").is_ok() {
        if let Some(parent) = baseline_path.parent() {
            fs::create_dir_all(parent).expect("create baseline directory");
        }
        fs::write(&baseline_path, &snapshot).expect("write baseline snapshot");
    }

    let expected = fs::read_to_string(&baseline_path).unwrap_or_else(|err| {
        panic!(
            "missing baseline file {}: {} (run with opForge_UPDATE_VM_BASELINE=1)",
            baseline_path.display(),
            err
        )
    });
    assert_eq!(snapshot, expected);
}

#[test]
fn m45gs02_vm_baseline_matches_reference() {
    let baseline_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vm/reference/m45gs02_vm_baseline.tsv");
    let snapshot = collect_m45gs02_vm_baseline_snapshot();

    if std::env::var("opForge_UPDATE_VM_BASELINE").is_ok() {
        if let Some(parent) = baseline_path.parent() {
            fs::create_dir_all(parent).expect("create baseline directory");
        }
        fs::write(&baseline_path, &snapshot).expect("write baseline snapshot");
    }

    let expected = fs::read_to_string(&baseline_path).unwrap_or_else(|err| {
        panic!(
            "missing baseline file {}: {} (run with opForge_UPDATE_VM_BASELINE=1)",
            baseline_path.display(),
            err
        )
    });
    assert_eq!(snapshot, expected);
}
