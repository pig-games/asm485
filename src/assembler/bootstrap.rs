// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::macro_processor::MacroExports;

use super::*;

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
    order: &'a mut Vec<(String, Vec<String>)>,
    stack: &'a mut Vec<String>,
    defines: &'a [String],
    pp_macro_depth: usize,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct OutputConfig {
    pub(crate) name: Option<String>,
    pub(crate) list_name: Option<String>,
    pub(crate) hex_name: Option<String>,
    pub(crate) bin_specs: Vec<BinOutputSpec>,
    pub(crate) fill_byte: Option<u8>,
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
pub(crate) struct RootMetadata {
    pub(crate) root_module_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) output_default: OutputConfig,
    pub(crate) output_by_target: HashMap<String, OutputConfig>,
    #[allow(dead_code)]
    pub(crate) linker_outputs: Vec<LinkerOutputDirective>,
    #[allow(dead_code)]
    pub(crate) mapfiles: Vec<MapFileDirective>,
    #[allow(dead_code)]
    pub(crate) export_sections: Vec<ExportSectionsDirective>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SectionKind {
    #[default]
    Code,
    Data,
    Bss,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SectionState {
    pub(crate) start_pc: u16,
    pub(crate) pc: u16,
    pub(crate) max_pc: u16,
    pub(crate) bytes: Vec<u8>,
    pub(crate) emitted: bool,
    pub(crate) layout_placed: bool,
    pub(crate) align: u16,
    pub(crate) kind: SectionKind,
    pub(crate) default_region: Option<String>,
    #[allow(dead_code)]
    pub(crate) base_addr: Option<u16>,
}

impl SectionState {
    pub(crate) fn size_bytes(&self) -> u16 {
        // `pc`/`max_pc` track section-local offsets, while `start_pc` can be
        // rebased during placement. Size must stay section-local.
        self.max_pc
    }

    pub(crate) fn is_bss(&self) -> bool {
        self.kind == SectionKind::Bss
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SectionOptions {
    pub(crate) align: Option<u16>,
    pub(crate) kind: Option<SectionKind>,
    pub(crate) region: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum PlacementDirective {
    Place {
        section: String,
        region: String,
        align: Option<u16>,
        span: Span,
    },
    Pack {
        region: String,
        sections: Vec<String>,
        span: Span,
    },
}

impl PlacementDirective {
    pub(crate) fn line(&self) -> u32 {
        match self {
            Self::Place { span, .. } | Self::Pack { span, .. } => span.line,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct PlacedSectionInfo {
    pub(crate) name: String,
    pub(crate) base: u16,
    pub(crate) size: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct RegionState {
    pub(crate) name: String,
    pub(crate) start: u32,
    pub(crate) end: u32, // inclusive
    pub(crate) cursor: u32,
    pub(crate) align: u16,
    pub(crate) placed: Vec<PlacedSectionInfo>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum MapSymbolsMode {
    All,
    Public,
    #[default]
    None,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct MapFileDirective {
    pub(crate) path: String,
    pub(crate) symbols: MapSymbolsMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ExportSectionsFormat {
    #[default]
    Bin,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ExportSectionsInclude {
    Bss,
    #[default]
    NoBss,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct ExportSectionsDirective {
    pub(crate) dir: String,
    pub(crate) format: ExportSectionsFormat,
    pub(crate) include: ExportSectionsInclude,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LinkerOutputFormat {
    #[default]
    Bin,
    Prg,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct LinkerOutputDirective {
    pub(crate) path: String,
    pub(crate) format: LinkerOutputFormat,
    pub(crate) sections: Vec<String>,
    pub(crate) contiguous: bool,
    pub(crate) image_start: Option<u16>,
    pub(crate) image_end: Option<u16>,
    pub(crate) fill: Option<u8>,
    pub(crate) loadaddr: Option<u16>,
}

impl RootMetadata {
    pub(crate) fn output_config_for_cpu(&self, cpu_name: &str) -> OutputConfig {
        let key = cpu_name.to_ascii_lowercase();
        let override_cfg = self.output_by_target.get(&key);
        self.output_default.merge_override(override_cfg)
    }

    pub(crate) fn output_config_mut(&mut self, target: Option<&str>) -> &mut OutputConfig {
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

pub(crate) fn root_module_id_from_lines(
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

pub(crate) fn resolve_output_base(
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

pub(crate) fn expand_source_file(
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
    Ok(pp.lines().to_vec())
}

fn expand_with_processor(
    mp: &mut MacroProcessor,
    lines: &[String],
) -> Result<Vec<String>, AsmRunError> {
    match mp.expand(lines) {
        Ok(lines) => Ok(lines),
        Err(err) => {
            let err_msg = AsmError::new(AsmErrorKind::Preprocess, err.message(), None);
            let mut diagnostics = Vec::new();
            if let Some(line) = err.line() {
                diagnostics.push(
                    Diagnostic::new(line, Severity::Error, err_msg.clone())
                        .with_column(err.column()),
                );
            }
            Err(AsmRunError::new(err_msg, diagnostics, lines.to_vec()))
        }
    }
}

fn parse_line_ast(line: &str, line_num: u32) -> Option<LineAst> {
    let mut parser = asm_parser::Parser::from_line(line, line_num).ok()?;
    parser.parse_line().ok()
}

pub(crate) fn expr_to_ident(expr: &Expr) -> Option<String> {
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

fn collect_use_directives_with_items(lines: &[String]) -> Vec<(String, Vec<String>)> {
    let mut uses = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(ast) = parse_line_ast(line, idx as u32 + 1) else {
            continue;
        };
        if let LineAst::Use {
            module_id, items, ..
        } = ast
        {
            let item_names: Vec<String> = items.iter().map(|item| item.name.clone()).collect();
            uses.push((module_id, item_names));
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
            if !capture {
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
            } else {
                // Nested .module inside the target block.
                depth += 1;
                captured.push(line.clone());
                continue;
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
    let source_lines = expand_source_file(&info.path, ctx.defines, ctx.pp_macro_depth)?;
    let module_lines = if info.has_explicit_modules {
        extract_module_block(&source_lines, module_id).ok_or_else(|| {
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
        source_lines
    };

    for dep in collect_use_directives(&module_lines) {
        load_module_recursive(&dep, ctx)?;
    }

    ctx.loaded.insert(canonical);
    ctx.order.push((module_id.to_string(), module_lines));
    ctx.stack.pop();
    Ok(())
}

#[derive(Debug)]
pub(crate) struct ModuleGraphResult {
    pub(crate) lines: Vec<String>,
    /// Macro/segment/statement names defined per module (canonical module ID → name set).
    pub(crate) module_macro_names: HashMap<String, HashSet<String>>,
}

pub(crate) fn load_module_graph(
    root_path: &Path,
    root_lines: Vec<String>,
    defines: &[String],
    pp_macro_depth: usize,
) -> Result<ModuleGraphResult, AsmRunError> {
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

    // Phase 1: expand macros per-module and collect exports.
    // `order` is dependency-first, so by the time we process a module,
    // all of its dependencies' exports are already collected.
    let mut module_exports: HashMap<String, MacroExports> = HashMap::new();
    let mut expanded_deps: Vec<Vec<String>> = Vec::new();

    for (module_id, module_lines) in &order {
        let canonical = canonical_module_id(module_id);
        let use_directives = collect_use_directives_with_items(module_lines);

        let mut mp = MacroProcessor::new();
        for (dep_id, items) in &use_directives {
            let dep_canonical = canonical_module_id(dep_id);
            if let Some(dep_exports) = module_exports.get(&dep_canonical) {
                if items.is_empty() {
                    mp.inject_all(dep_exports);
                } else {
                    mp.inject_from(dep_exports, items);
                }
            }
        }

        let expanded = expand_with_processor(&mut mp, module_lines)?;
        module_exports.insert(canonical, mp.take_native_exports());
        expanded_deps.push(expanded);
    }

    // Phase 2: expand root with only its explicitly imported macros.
    let root_uses = collect_use_directives_with_items(&root_lines);
    let mut mp = MacroProcessor::new();
    for (dep_id, items) in &root_uses {
        let dep_canonical = canonical_module_id(dep_id);
        if let Some(dep_exports) = module_exports.get(&dep_canonical) {
            if items.is_empty() {
                mp.inject_all(dep_exports);
            } else {
                mp.inject_from(dep_exports, items);
            }
        }
    }

    let expanded_root = expand_with_processor(&mut mp, &root_lines)?;

    let mut combined = Vec::new();
    for dep_lines in expanded_deps {
        combined.extend(dep_lines);
    }
    combined.extend(expanded_root);

    let module_macro_names: HashMap<String, HashSet<String>> = module_exports
        .into_iter()
        .map(|(id, exports)| (id, exports.names()))
        .collect();

    Ok(ModuleGraphResult {
        lines: combined,
        module_macro_names,
    })
}
