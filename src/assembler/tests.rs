use super::{
    build_export_sections_payloads, build_linker_output_payload, build_mapfile_text,
    expand_source_file, load_module_graph, root_module_id_from_lines, AsmErrorKind, AsmLine,
    Assembler, ExportSectionsFormat, ExportSectionsInclude, LineStatus, LinkerOutputDirective,
    LinkerOutputFormat, ListingWriter, MapFileDirective, MapSymbolsMode, RegionState, RootMetadata,
    SectionState, Severity,
};
use crate::core::macro_processor::MacroProcessor;
use crate::core::registry::ModuleRegistry;
use crate::core::symbol_table::{SymbolTable, SymbolTableResult, SymbolVisibility};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{
    M6502CpuModule, MOS6502FamilyModule, CPU_ID as m6502_cpu_id,
};
use crate::families::mos6502::{AddressMode, FAMILY_INSTRUCTION_TABLE};
use crate::i8085::module::{I8085CpuModule, CPU_ID as i8085_cpu_id};
use crate::m65816::instructions::CPU_INSTRUCTION_TABLE as M65816_INSTRUCTION_TABLE;
use crate::m65816::module::M65816CpuModule;
use crate::m65816::module::CPU_ID as m65816_cpu_id;
use crate::m65c02::instructions::CPU_INSTRUCTION_TABLE as M65C02_INSTRUCTION_TABLE;
use crate::m65c02::module::{M65C02CpuModule, CPU_ID as m65c02_cpu_id};
#[cfg(feature = "opthread-runtime")]
use crate::opthread::builder::build_hierarchy_chunks_from_registry;
#[cfg(feature = "opthread-runtime")]
use crate::opthread::hierarchy::ScopedOwner;
#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
use crate::opthread::intel8080_vm::mode_key_for_instruction_entry;
#[cfg(feature = "opthread-runtime")]
use crate::opthread::package::ModeSelectorDescriptor;
#[cfg(feature = "opthread-runtime")]
use crate::opthread::rollout::{
    family_runtime_mode, family_runtime_rollout_policy, package_runtime_default_enabled_for_family,
    FamilyRuntimeMode,
};
#[cfg(feature = "opthread-runtime")]
use crate::opthread::runtime::HierarchyExecutionModel;
#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
use crate::z80::module::{Z80CpuModule, CPU_ID as z80_cpu_id};
use std::collections::{HashMap, HashSet};
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
    registry.register_cpu(Box::new(M65816CpuModule));
    registry
}

fn make_asm_line<'a>(symbols: &'a mut SymbolTable, registry: &'a ModuleRegistry) -> AsmLine<'a> {
    AsmLine::new(symbols, registry)
}

fn process_line(asm: &mut AsmLine<'_>, line: &str, addr: u32, pass: u8) -> LineStatus {
    asm.process(line, 1, addr, pass)
}

fn assemble_bytes(cpu: crate::core::cpu::CpuType, line: &str) -> Vec<u8> {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    #[cfg(feature = "opthread-runtime")]
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, cpu, &registry, false);
    #[cfg(not(feature = "opthread-runtime"))]
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
    #[cfg(feature = "opthread-runtime")]
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, cpu, &registry, false);
    #[cfg(not(feature = "opthread-runtime"))]
    let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message)
}

#[cfg(feature = "opthread-runtime")]
fn assemble_line_with_runtime_mode(
    cpu: crate::core::cpu::CpuType,
    line: &str,
    enable_opthread_runtime: bool,
) -> (LineStatus, Option<String>, Vec<u8>) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm =
        AsmLine::with_cpu_runtime_mode(&mut symbols, cpu, &registry, enable_opthread_runtime);
    #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
    if enable_opthread_runtime {
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
            asm.opthread_execution_model = Some(
                HierarchyExecutionModel::from_registry(&registry)
                    .expect("runtime execution model from registry"),
            );
        }
    }
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec())
}

#[cfg(feature = "opthread-runtime")]
fn assemble_line_with_runtime_mode_no_injection(
    cpu: crate::core::cpu::CpuType,
    line: &str,
    enable_opthread_runtime: bool,
) -> (LineStatus, Option<String>, Vec<u8>, bool) {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm =
        AsmLine::with_cpu_runtime_mode(&mut symbols, cpu, &registry, enable_opthread_runtime);
    let has_model = asm.opthread_execution_model.is_some();
    asm.clear_conditionals();
    asm.clear_scopes();
    let status = asm.process(line, 1, 0, 2);
    let message = asm.error().map(|err| err.to_string());
    (status, message, asm.bytes().to_vec(), has_model)
}

#[cfg(feature = "opthread-runtime")]
fn assemble_source_entries_with_runtime_mode(
    lines: &[&str],
    enable_opthread_runtime: bool,
) -> Result<(Vec<(u32, u8)>, Vec<String>), String> {
    let mut assembler = Assembler::new();
    assembler.set_opthread_runtime_enabled(enable_opthread_runtime);
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
    let root_lines = expand_source_file(root_path, &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let graph = load_module_graph(root_path, root_lines.clone(), &[], 64)
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
        .header("opForge 8085 Assembler v1.0")
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

#[cfg(feature = "opthread-runtime")]
fn assemble_example_entries_with_runtime_mode(
    asm_path: &Path,
    enable_opthread_runtime: bool,
) -> Result<(Vec<(u32, u8)>, Vec<String>), String> {
    let root_lines =
        expand_source_file(asm_path, &[], 64).map_err(|err| format!("Preprocess failed: {err}"))?;
    let graph = load_module_graph(asm_path, root_lines.clone(), &[], 64)
        .map_err(|err| format!("Preprocess failed: {err}"))?;
    let expanded_lines = graph.lines;

    let mut assembler = Assembler::new();
    assembler.set_opthread_runtime_enabled(enable_opthread_runtime);
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

fn first_example_error(assembler: &Assembler) -> Option<String> {
    assembler
        .diagnostics
        .iter()
        .find(|diag| diag.severity == Severity::Error)
        .map(|diag| format!("Assembly failed: {}", diag.error.message()))
}

fn assemble_example_error(asm_path: &Path) -> Option<String> {
    let asm_name = asm_path.to_string_lossy().to_string();

    let root_path = Path::new(&asm_name);
    let root_lines = match expand_source_file(root_path, &[], 64) {
        Ok(lines) => lines,
        Err(err) => return Some(format!("Preprocess failed: {err}")),
    };
    let (expanded_lines, module_macro_names) =
        match load_module_graph(root_path, root_lines.clone(), &[], 64) {
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
    if listing.header("opForge 8085 Assembler v1.0").is_ok() {
        let _ = assembler.pass2(&expanded_lines, &mut listing);
    }
    if let Err(err) = validate_example_linker_outputs(&assembler) {
        return Some(err);
    }

    first_example_error(&assembler)
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
    let combined = load_module_graph(&root_path, root_lines, &[], 32)
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
        "linker_regions_phase6_fill_in_bss" => {
            Some("Assembly failed: .fill is not allowed in kind=bss section (current kind=bss)")
        }
        _ => None,
    }
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
    let status = process_line(&mut asm, "    .align $10001", 1, 1);
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
    let status = process_line(&mut asm, "    .align $10001", 1, 1);
    assert_eq!(status, LineStatus::DirDs);
    assert_eq!(asm.aux_value(), 0x10000);
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
    asm.sections.insert(
        "code".to_string(),
        SectionState {
            base_addr: Some(1),
            ..SectionState::default()
        },
    );
    asm.section_symbol_sections
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
    asm.cpu_program_address_max = u32::MAX;
    asm.regions.insert(
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
    asm.sections.insert(
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
fn encoding_directive_accepts_alias_and_string_name() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .encoding \"petscii\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .byte \"a\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    assert_eq!(asm.bytes(), &[0x41]);

    let status = process_line(&mut asm, "    .enc ascii", 0, 2);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .byte \"a\"", 0, 2);
    assert_eq!(status, LineStatus::Ok);
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
fn string_expressions_use_active_encoding() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, "    .enc petscii", 0, 1);
    assert_eq!(status, LineStatus::Ok);

    let status = process_line(&mut asm, "VAL .const 'a'", 0, 1);
    assert_eq!(status, LineStatus::DirEqu);
    assert_eq!(asm.symbols().lookup("VAL"), Some(0x41));
}

#[test]
fn module_entry_resets_text_encoding_to_default() {
    let assembler = run_passes(&[
        ".module first",
        "    .enc petscii",
        "    .byte \"a\"",
        ".endmodule",
        ".module second",
        "    .byte \"a\"",
        ".endmodule",
    ]);
    let entries = assembler.image().entries().expect("entries");
    assert_eq!(entries, vec![(0x0000, 0x41), (0x0001, 0x61)]);
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
    asm.current_section = Some("code".to_string());
    asm.sections.insert(
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
    asm.current_section = Some("code".to_string());
    asm.sections.insert(
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
            .header("opForge 8085 Assembler v1.0")
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
        asm.cpu_state_flags
            .get(crate::m65816::state::EMULATION_MODE_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::ACCUMULATOR_8BIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::INDEX_8BIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::DATA_BANK_KEY)
            .copied(),
        Some(0x12)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::DATA_BANK_EXPLICIT_KEY)
            .copied(),
        Some(1)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::PROGRAM_BANK_KEY)
            .copied(),
        Some(0x34)
    );
    assert_eq!(
        asm.cpu_state_flags
            .get(crate::m65816::state::PROGRAM_BANK_EXPLICIT_KEY)
            .copied(),
        Some(1)
    );
    assert_eq!(
        asm.cpu_state_flags
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
        asm.cpu_state_flags
            .get(crate::m65816::state::DATA_BANK_EXPLICIT_KEY)
            .copied(),
        Some(0)
    );
    assert_eq!(
        asm.cpu_state_flags
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
    assert!(message.unwrap_or_default().contains("out of 16-bit range"));

    let (status, message) = assemble_line_status(m65c02_cpu_id, "    MVN $01,$02");
    assert_eq!(status, LineStatus::Error);
    assert!(message
        .unwrap_or_default()
        .contains("65816-only addressing mode not supported on 65C02"));

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
    let mut section = SectionState::default();
    section.base_addr = Some(u32::MAX);
    section.bytes = vec![0xaa, 0xbb];
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
    let mut section = SectionState::default();
    section.base_addr = Some(u32::MAX);
    section.bytes = vec![0xaa, 0xbb];
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

#[cfg(feature = "opthread-parity")]
#[test]
fn opthread_parity_smoke_instruction_bytes_and_diagnostics() {
    use crate::opthread::builder::build_hierarchy_package_from_registry;
    use crate::opthread::package::load_hierarchy_package;
    use std::fs;
    use std::path::Path;

    let registry = default_registry();
    let package_bytes =
        build_hierarchy_package_from_registry(&registry).expect("build hierarchy package");
    let package = load_hierarchy_package(&package_bytes).expect("load hierarchy package");
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/opthread/vectors");
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_base_cpu_path_uses_package_forms() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_model_is_available_for_mos6502_family_cpus() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    for cpu in [m6502_cpu_id, m65c02_cpu_id, m65816_cpu_id] {
        let asm = AsmLine::with_cpu_runtime_mode(&mut symbols, cpu, &registry, true);
        assert!(
            asm.opthread_execution_model.is_some(),
            "expected runtime execution model for {}",
            cpu.as_str()
        );
    }
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_model_stays_disabled_for_non_mos6502_family_cpu() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();

    let i8085_asm = AsmLine::with_cpu_runtime_mode(&mut symbols, i8085_cpu_id, &registry, true);
    assert!(i8085_asm.opthread_execution_model.is_none());

    let z80_asm = AsmLine::with_cpu_runtime_mode(&mut symbols, z80_cpu_id, &registry, true);
    assert!(z80_asm.opthread_execution_model.is_none());
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_rollout_criteria_all_registered_families_have_policy_and_checklist() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_rollout_criteria_staged_families_use_native_path_when_runtime_enabled() {
    assert_eq!(
        family_runtime_mode("intel8080"),
        FamilyRuntimeMode::StagedVerification
    );
    assert!(!package_runtime_default_enabled_for_family("intel8080"));

    for (cpu, line) in [
        (i8085_cpu_id, "    MVI A,55h"),
        (z80_cpu_id, "    LD A,55h"),
    ] {
        let native = assemble_line_with_runtime_mode_no_injection(cpu, line, false);
        let runtime = assemble_line_with_runtime_mode_no_injection(cpu, line, true);
        assert!(
            !runtime.3,
            "staged family should not auto-enable opthread model for {}",
            cpu.as_str()
        );
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_rollout_criteria_mos6502_parity_and_determinism_gate() {
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

#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
#[test]
fn opthread_runtime_intel8085_path_uses_package_forms() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, i8085_cpu_id, &registry, true);
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

#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
#[test]
fn opthread_runtime_z80_dialect_path_uses_package_forms() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, z80_cpu_id, &registry, true);
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

#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
#[test]
fn opthread_runtime_intel8080_family_rewrite_pairs_match_native_mode() {
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

#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
#[test]
fn opthread_runtime_intel8085_extension_parity_corpus_matches_native_mode() {
    let corpus = ["    RIM", "    SIM"];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(i8085_cpu_id, line, false);
        let runtime = assemble_line_with_runtime_mode(i8085_cpu_id, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[cfg(all(
    feature = "opthread-runtime",
    feature = "opthread-runtime-intel8080-scaffold"
))]
#[test]
fn opthread_runtime_z80_extension_parity_corpus_matches_native_mode() {
    let corpus = ["    DJNZ $0004", "    RLC B"];

    for line in corpus {
        let native = assemble_line_with_runtime_mode(z80_cpu_id, line, false);
        let runtime = assemble_line_with_runtime_mode(z80_cpu_id, line, true);
        assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
        assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
        assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
    }
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_missing_tabl_program_errors_instead_of_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m6502_cpu_id, &registry, true);

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
    assert!(message
        .to_ascii_lowercase()
        .contains("missing opthread vm program"));
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m6502_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m6502_cpu_id, &registry, true);

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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65c02_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m65c02_cpu_id, &registry, true);

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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65816_missing_selector_errors_instead_of_resolve_fallback() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m65816_cpu_id, &registry, true);

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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_parity_corpus_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_expr_resolver_rejects_unsupported_shape_without_fallback() {
    let line = "    LDA ($10,S),Y";
    let native = assemble_line_with_runtime_mode(m6502_cpu_id, line, false);
    let runtime = assemble_line_with_runtime_mode(m6502_cpu_id, line, true);
    assert_eq!(runtime.0, native.0, "status mismatch for '{}'", line);
    assert_eq!(runtime.1, native.1, "diagnostic mismatch for '{}'", line);
    assert_eq!(runtime.2, native.2, "bytes mismatch for '{}'", line);
}

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_non_65816_force_suffix_diagnostics_match_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_pathological_line_corpus_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65816_width_edge_program_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_selector_conflict_reports_deterministic_error() {
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
        let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m6502_cpu_id, &registry, true);
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
        let mut asm = AsmLine::with_cpu_runtime_mode(&mut symbols, m6502_cpu_id, &registry, true);
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_example_programs_match_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos6502_relocation_heavy_program_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65c02_example_programs_match_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65816_example_programs_match_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_mos_family_diagnostic_boundary_parity_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65c02_extension_parity_corpus_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65816_extension_parity_corpus_matches_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65c02_table_modes_match_native_mode() {
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

#[cfg(feature = "opthread-runtime")]
#[test]
fn opthread_runtime_m65816_table_modes_match_native_mode() {
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
        let diag = message
            .unwrap_or_default()
            .replace('\t', " ")
            .replace('\n', " ");
        rows.push(format!("{case_id}\t{line}\t{status_name}\t{bytes}\t{diag}"));
    }

    rows.join("\n") + "\n"
}

#[test]
fn mos6502_native_baseline_matches_reference() {
    let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/opthread/reference/mos6502_native_baseline.tsv");
    let snapshot = collect_mos6502_native_baseline_snapshot();

    if std::env::var("opForge_UPDATE_OPTHREAD_BASELINE").is_ok() {
        if let Some(parent) = baseline_path.parent() {
            fs::create_dir_all(parent).expect("create baseline directory");
        }
        fs::write(&baseline_path, &snapshot).expect("write baseline snapshot");
    }

    let expected = fs::read_to_string(&baseline_path).unwrap_or_else(|err| {
        panic!(
            "missing baseline file {}: {} (run with opForge_UPDATE_OPTHREAD_BASELINE=1)",
            baseline_path.display(),
            err
        )
    });
    assert_eq!(snapshot, expected);
}
