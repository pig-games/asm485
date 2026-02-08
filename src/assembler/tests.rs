use super::{
    build_export_sections_payloads, build_linker_output_payload, build_mapfile_text,
    expand_source_file, load_module_graph, root_module_id_from_lines, AsmErrorKind, AsmLine,
    Assembler, ExportSectionsFormat, ExportSectionsInclude, LineStatus, LinkerOutputFormat,
    ListingWriter, MapSymbolsMode, RootMetadata, Severity,
};
use crate::core::macro_processor::MacroProcessor;
use crate::core::registry::ModuleRegistry;
use crate::core::symbol_table::SymbolTable;
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::{I8085CpuModule, CPU_ID as i8085_cpu_id};
use crate::m65c02::module::{M65C02CpuModule, CPU_ID as m65c02_cpu_id};
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

fn make_asm_line<'a>(symbols: &'a mut SymbolTable, registry: &'a ModuleRegistry) -> AsmLine<'a> {
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
    assert_eq!(
        status,
        LineStatus::Ok,
        "assembly failed for '{line}' with {:?}",
        asm.error().map(|err| err.to_string())
    );
    asm.bytes().to_vec()
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

#[test]
fn module_loader_allows_cross_module_segment_expansion() {
    let dir = create_temp_dir("module-segment-cross");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .org $0000\n    .lib.EMIT $AA\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nEMIT .segment v\n    .byte .v\n.endsegment\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&combined, &mut listing).expect("pass2");
    assert_eq!(
        pass2.errors, 0,
        "pass2 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut hex = Vec::new();
    assembler
        .image()
        .write_hex_file(&mut hex, None)
        .expect("hex output");
    let hex_text = String::from_utf8_lossy(&hex);
    assert!(
        hex_text.contains(":02000000AA76DE"),
        "unexpected hex output: {hex_text}"
    );
}

#[test]
fn module_loader_allows_cross_module_statement_expansion() {
    let dir = create_temp_dir("module-statement-cross");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .org $0000\n    lib.PUSHB $5A\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&combined, &mut listing).expect("pass2");
    assert_eq!(
        pass2.errors, 0,
        "pass2 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut hex = Vec::new();
    assembler
        .image()
        .write_hex_file(&mut hex, None)
        .expect("hex output");
    let hex_text = String::from_utf8_lossy(&hex);
    assert!(
        hex_text.contains(":020000005A762E"),
        "unexpected hex output: {hex_text}"
    );
}

#[test]
fn module_loader_bare_use_allows_qualified_macro_expansion() {
    let dir = create_temp_dir("module-macro-cross");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .org $0000\n    .lib.EMIT_PAIR $AA, $BB\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nEMIT_PAIR .macro a, b\n    .byte .a\n    .byte .b\n.endmacro\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&combined, &mut listing).expect("pass2");
    assert_eq!(
        pass2.errors, 0,
        "pass2 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut hex = Vec::new();
    assembler
        .image()
        .write_hex_file(&mut hex, None)
        .expect("hex output");
    let hex_text = String::from_utf8_lossy(&hex);
    assert!(
        hex_text.contains(":03000000AABB7622"),
        "unexpected hex output: {hex_text}"
    );
}

#[test]
fn module_loader_bare_use_alias_allows_qualified_segment_expansion() {
    let dir = create_temp_dir("module-segment-alias-qualified");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib as L\n    .org $0000\n    .L.EMIT $AA\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nEMIT .segment v\n    .byte .v\n.endsegment\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );
}

#[test]
fn module_loader_selective_import_includes_segment() {
    let dir = create_temp_dir("module-segment-selective");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (EMIT)\n    .org $0000\n    .EMIT $AA\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nEMIT .segment v\n    .byte .v\n.endsegment\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );

    let mut listing_out = Vec::new();
    let mut listing = ListingWriter::new(&mut listing_out, false);
    let pass2 = assembler.pass2(&combined, &mut listing).expect("pass2");
    assert_eq!(
        pass2.errors, 0,
        "pass2 diagnostics: {:?}",
        assembler.diagnostics
    );
}

#[test]
fn module_loader_selective_import_excludes_segment() {
    let dir = create_temp_dir("module-segment-not-imported");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    // Only import VAL, not EMIT — segment should NOT be available
    write_file(
        &root_path,
        ".module app\n    .use lib (VAL)\n    .org $0000\n    .byte VAL\n    .EMIT $AA\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nVAL .const 7\nEMIT .segment v\n    .byte .v\n.endsegment\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(
        pass1.errors > 0,
        "Expected errors because EMIT segment was not imported"
    );
}

#[test]
fn module_loader_selective_import_private_segment_emits_private_diagnostic() {
    let dir = create_temp_dir("module-segment-private-selective");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (EMIT)\n    .org $0000\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .priv\nEMIT .segment v\n    .byte .v\n.endsegment\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(pass1.errors > 0, "Expected private import diagnostic");
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error.kind() == AsmErrorKind::Symbol && diag.error.message().contains("private")
    }));
}

#[test]
fn module_loader_selective_import_includes_statement() {
    let dir = create_temp_dir("module-statement-selective");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (PUSHB)\n    .org $0000\n    PUSHB $5A\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
    );
}

#[test]
fn module_loader_selective_import_excludes_statement() {
    let dir = create_temp_dir("module-statement-not-imported");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    // Only import VAL, not PUSHB — statement should NOT be available
    write_file(
        &root_path,
        ".module app\n    .use lib (VAL)\n    .org $0000\n    .byte VAL\n    PUSHB $5A\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nVAL .const 7\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(
        pass1.errors > 0,
        "Expected errors because PUSHB statement was not imported"
    );
}

#[test]
fn module_loader_selective_import_private_statement_emits_private_diagnostic() {
    let dir = create_temp_dir("module-statement-private-selective");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (PUSHB)\n    .org $0000\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .priv\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(pass1.errors > 0, "Expected private import diagnostic");
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error.kind() == AsmErrorKind::Symbol && diag.error.message().contains("private")
    }));
}

#[test]
fn module_loader_bare_use_does_not_import_statement_unqualified() {
    let dir = create_temp_dir("module-statement-bare-use");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .org $0000\n    PUSHB $5A\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(
        pass1.errors > 0,
        "Expected errors because PUSHB statement was not imported by bare .use"
    );
}

#[test]
fn module_loader_bare_use_does_not_import_macro_unqualified() {
    let dir = create_temp_dir("module-macro-bare-use");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib\n    .org $0000\n    .EMIT_PAIR $AA, $BB\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nEMIT_PAIR .macro a, b\n    .byte .a\n    .byte .b\n.endmacro\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(
        pass1.errors > 0,
        "Expected errors because EMIT_PAIR macro was not imported by bare .use"
    );
}

#[test]
fn module_loader_selective_import_private_macro_emits_private_diagnostic() {
    let dir = create_temp_dir("module-macro-private-selective");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (EMIT_PAIR)\n    .org $0000\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .priv\nEMIT_PAIR .macro a, b\n    .byte .a\n    .byte .b\n.endmacro\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert!(pass1.errors > 0, "Expected private import diagnostic");
    assert!(assembler.diagnostics.iter().any(|diag| {
        diag.error.kind() == AsmErrorKind::Symbol && diag.error.message().contains("private")
    }));
}

#[test]
fn module_loader_wildcard_import_includes_runtime_and_statement() {
    let dir = create_temp_dir("module-wildcard-runtime-statement");
    let root_path = dir.join("main.asm");
    let lib_path = dir.join("lib.asm");

    write_file(
        &root_path,
        ".module app\n    .use lib (*)\n    .org $0000\n    .byte VAL\n    PUSHB $5A\n    hlt\n.endmodule\n",
    );
    write_file(
        &lib_path,
        ".module lib\n    .pub\nVAL .const 7\n.statement PUSHB byte:v\n    .byte .v\n.endstatement\n.endmodule\n",
    );

    let root_lines = expand_source_file(&root_path, &[], 32).expect("expand root");
    let graph = load_module_graph(&root_path, root_lines, &[], 32).expect("load graph");
    let combined = graph.lines;

    let mut assembler = Assembler::new();
    assembler.root_metadata.root_module_id = Some("app".to_string());
    assembler.module_macro_names = graph.module_macro_names;
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&combined);
    assert_eq!(
        pass1.errors, 0,
        "pass1 diagnostics: {:?}",
        assembler.diagnostics
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
fn z80_ld_absolute_indirect_forms_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    LD A,(1234h)");
    assert_eq!(bytes, vec![0x3A, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (1234h),A");
    assert_eq!(bytes, vec![0x32, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD BC,(1234h)");
    assert_eq!(bytes, vec![0xED, 0x4B, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (1234h),BC");
    assert_eq!(bytes, vec![0xED, 0x43, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD HL,(1234h)");
    assert_eq!(bytes, vec![0x2A, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (1234h),HL");
    assert_eq!(bytes, vec![0x22, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD IX,(1234h)");
    assert_eq!(bytes, vec![0xDD, 0x2A, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (1234h),IX");
    assert_eq!(bytes, vec![0xDD, 0x22, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD IY,(1234h)");
    assert_eq!(bytes, vec![0xFD, 0x2A, 0x34, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (1234h),IY");
    assert_eq!(bytes, vec![0xFD, 0x22, 0x34, 0x12]);
}

#[test]
fn z80_ex_sp_hl_uses_xthl_opcode() {
    let bytes = assemble_bytes(z80_cpu_id, "    EX DE,HL");
    assert_eq!(bytes, vec![0xEB]);

    let bytes = assemble_bytes(z80_cpu_id, "    EX (SP),HL");
    assert_eq!(bytes, vec![0xE3]);

    let bytes = assemble_bytes(z80_cpu_id, "    EX AF,AF'");
    assert_eq!(bytes, vec![0x08]);
}

#[test]
fn z80_io_forms_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    IN A,(12h)");
    assert_eq!(bytes, vec![0xDB, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    OUT (34h),A");
    assert_eq!(bytes, vec![0xD3, 0x34]);

    let bytes = assemble_bytes(z80_cpu_id, "    IN B,(C)");
    assert_eq!(bytes, vec![0xED, 0x40]);

    let bytes = assemble_bytes(z80_cpu_id, "    OUT (C),B");
    assert_eq!(bytes, vec![0xED, 0x41]);
}

#[test]
fn z80_jp_ix_iy_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    JP IX");
    assert_eq!(bytes, vec![0xDD, 0xE9]);

    let bytes = assemble_bytes(z80_cpu_id, "    JP IY");
    assert_eq!(bytes, vec![0xFD, 0xE9]);

    let bytes = assemble_bytes(z80_cpu_id, "    JP (IX)");
    assert_eq!(bytes, vec![0xDD, 0xE9]);

    let bytes = assemble_bytes(z80_cpu_id, "    JP (IY)");
    assert_eq!(bytes, vec![0xFD, 0xE9]);
}

#[test]
fn z80_half_index_register_forms_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    LD IXH,A");
    assert_eq!(bytes, vec![0xDD, 0x67]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD A,IXL");
    assert_eq!(bytes, vec![0xDD, 0x7D]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD IYH,12h");
    assert_eq!(bytes, vec![0xFD, 0x26, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    INC IXH");
    assert_eq!(bytes, vec![0xDD, 0x24]);

    let bytes = assemble_bytes(z80_cpu_id, "    DEC IYL");
    assert_eq!(bytes, vec![0xFD, 0x2D]);

    let bytes = assemble_bytes(z80_cpu_id, "    ADD A,IXH");
    assert_eq!(bytes, vec![0xDD, 0x84]);

    let bytes = assemble_bytes(z80_cpu_id, "    ADC A,IYL");
    assert_eq!(bytes, vec![0xFD, 0x8D]);

    let bytes = assemble_bytes(z80_cpu_id, "    SUB IXL");
    assert_eq!(bytes, vec![0xDD, 0x95]);

    let bytes = assemble_bytes(z80_cpu_id, "    SBC A,IXH");
    assert_eq!(bytes, vec![0xDD, 0x9C]);

    let bytes = assemble_bytes(z80_cpu_id, "    AND IYL");
    assert_eq!(bytes, vec![0xFD, 0xA5]);

    let bytes = assemble_bytes(z80_cpu_id, "    XOR IXH");
    assert_eq!(bytes, vec![0xDD, 0xAC]);

    let bytes = assemble_bytes(z80_cpu_id, "    OR IXL");
    assert_eq!(bytes, vec![0xDD, 0xB5]);

    let bytes = assemble_bytes(z80_cpu_id, "    CP IYL");
    assert_eq!(bytes, vec![0xFD, 0xBD]);
}

#[test]
fn z80_indexed_non_cb_forms_encode() {
    let bytes = assemble_bytes(z80_cpu_id, "    LD A,(IX+1)");
    assert_eq!(bytes, vec![0xDD, 0x7E, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD B,(IY+2)");
    assert_eq!(bytes, vec![0xFD, 0x46, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (IX+1),A");
    assert_eq!(bytes, vec![0xDD, 0x77, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (IY+2),B");
    assert_eq!(bytes, vec![0xFD, 0x70, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    LD (IX+1),12h");
    assert_eq!(bytes, vec![0xDD, 0x36, 0x01, 0x12]);

    let bytes = assemble_bytes(z80_cpu_id, "    INC (IX+1)");
    assert_eq!(bytes, vec![0xDD, 0x34, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    DEC (IY+2)");
    assert_eq!(bytes, vec![0xFD, 0x35, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    ADD A,(IX+1)");
    assert_eq!(bytes, vec![0xDD, 0x86, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    ADC A,(IY+2)");
    assert_eq!(bytes, vec![0xFD, 0x8E, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    SUB (IX+1)");
    assert_eq!(bytes, vec![0xDD, 0x96, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    SBC A,(IY+2)");
    assert_eq!(bytes, vec![0xFD, 0x9E, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    AND (IX+1)");
    assert_eq!(bytes, vec![0xDD, 0xA6, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    XOR (IY+2)");
    assert_eq!(bytes, vec![0xFD, 0xAE, 0x02]);

    let bytes = assemble_bytes(z80_cpu_id, "    OR (IX+1)");
    assert_eq!(bytes, vec![0xDD, 0xB6, 0x01]);

    let bytes = assemble_bytes(z80_cpu_id, "    CP (IY+2)");
    assert_eq!(bytes, vec![0xFD, 0xBE, 0x02]);
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
fn res_overflow_reports_total_and_unit() {
    let mut symbols = SymbolTable::new();
    let registry = default_registry();
    let mut asm = make_asm_line(&mut symbols, &registry);

    let status = process_line(&mut asm, ".section vars, kind=bss", 0, 1);
    assert_eq!(status, LineStatus::Ok);
    let status = process_line(&mut asm, "    .res long, 20000", 0, 1);
    assert_eq!(status, LineStatus::Error);
    assert!(asm.error_message().contains("total size"));
    assert!(asm.error_message().contains("unit=4"));
    assert!(asm.error_message().contains("count=20000"));
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
fn statement_dollar_hex_suffix_chars_assemble_correctly() {
    // Regression: $BB, $AB, $0B etc. failed in statement byte-capture matching
    // because parse_number treated the trailing B as a binary suffix before
    // recognising the $ hex prefix.
    let lines = vec![
        ".statement PUSHB byte:v".to_string(),
        "    .byte .v".to_string(),
        ".endstatement".to_string(),
        "    .org $0000".to_string(),
        "    PUSHB $AA".to_string(),
        "    PUSHB $BB".to_string(),
        "    PUSHB $AB".to_string(),
        "    PUSHB $0B".to_string(),
        "    PUSHB $FB".to_string(),
    ];
    let mut mp = MacroProcessor::new();
    let expanded = mp.expand(&lines).expect("expand");

    let mut assembler = Assembler::new();
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&expanded);
    assert_eq!(pass1.errors, 0, "pass1 errors: {:?}", assembler.diagnostics);

    let mut output = Vec::new();
    let mut listing = ListingWriter::new(&mut output, false);
    let _ = listing.header("test");
    let pass2 = assembler.pass2(&expanded, &mut listing).expect("pass2");
    assert_eq!(pass2.errors, 0, "pass2 errors: {:?}", assembler.diagnostics);

    let mut hex = Vec::new();
    assembler
        .image()
        .write_hex_file(&mut hex, None)
        .expect("hex");
    let hex_text = String::from_utf8_lossy(&hex);
    // Expected bytes at $0000: AA BB AB 0B FB
    assert!(
        hex_text.contains(":05000000AABBAB0BFBE5"),
        "unexpected hex: {hex_text}"
    );
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
