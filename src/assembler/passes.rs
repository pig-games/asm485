//! Assembler run/pass orchestration.
//!
//! This module owns CLI-driven run flow, formatter input resolution, source
//! expansion/module loading, and pass1/pass2 execution sequencing.

use super::*;

/// Run the assembler with command-line arguments.
pub(super) fn run() -> Result<Vec<AsmRunReport>, AsmRunError> {
    let cli = Cli::parse();
    run_with_cli(&cli)
}

pub(super) fn run_with_cli(cli: &Cli) -> Result<Vec<AsmRunReport>, AsmRunError> {
    let config = validate_cli(cli)?;

    let mut reports = Vec::new();
    for asm_path in &config.input_paths {
        let (asm_name, input_base) = input_base_from_path(asm_path, &config.input_extensions)?;
        let report = run_one(cli, &asm_name, &input_base, &config)?;
        reports.push(report);
    }

    if config.warning_policy.treat_warnings_as_errors {
        let mut warning_diags = Vec::new();
        let mut source_lines = Vec::new();
        for report in &reports {
            if source_lines.is_empty() {
                source_lines = report.source_lines().to_vec();
            }
            for diag in report.diagnostics() {
                if diag.severity == Severity::Warning {
                    let mut warning = diag.clone();
                    warning.severity = Severity::Error;
                    warning_diags.push(warning);
                }
            }
        }
        if !warning_diags.is_empty() {
            return Err(AsmRunError::new(
                AsmError::new(
                    AsmErrorKind::Assembler,
                    "Warnings treated as errors (-Werror)",
                    None,
                ),
                warning_diags,
                source_lines,
            ));
        }
    }

    Ok(reports)
}

/// Resolve source files targeted by formatter mode.
///
/// File inputs map to their resolved root source file.
/// Directory inputs expand to the root module plus all linked module/include
/// source files discovered through the module graph loader.
pub(super) fn resolve_formatter_input_paths(
    config: &cli::CliConfig,
) -> Result<Vec<PathBuf>, AsmRunError> {
    let mut resolved = Vec::new();
    for input_path in &config.input_paths {
        if input_path.is_dir() {
            resolved.extend(resolve_formatter_module_paths(input_path, config)?);
            continue;
        }
        let (asm_name, _) = input_base_from_path(input_path, &config.input_extensions)?;
        resolved.push(PathBuf::from(asm_name));
    }
    Ok(resolved)
}

fn resolve_formatter_module_paths(
    input_path: &Path,
    config: &cli::CliConfig,
) -> Result<Vec<PathBuf>, AsmRunError> {
    let (asm_name, _) = input_base_from_path(input_path, &config.input_extensions)?;
    let root_path = PathBuf::from(asm_name);
    let (root_lines, root_dependency_files) = expand_source_file_with_dependencies(
        &root_path,
        &config.defines,
        &config.include_paths,
        config.pp_macro_depth,
    )?;
    let graph = load_module_graph(
        &root_path,
        root_lines,
        &config.defines,
        &config.include_paths,
        &config.module_paths,
        config.pp_macro_depth,
    )?;

    let mut files = HashSet::new();
    for path in root_dependency_files {
        if is_formatter_source_path(&path, &config.input_extensions) {
            files.insert(path);
        }
    }
    for path in graph.dependency_files {
        if is_formatter_source_path(&path, &config.input_extensions) {
            files.insert(path);
        }
    }
    files.insert(root_path);

    let mut sorted: Vec<PathBuf> = files.into_iter().collect();
    sorted.sort();
    Ok(sorted)
}

fn is_formatter_source_path(path: &Path, ext_policy: &cli::InputExtensionPolicy) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    ext_policy
        .asm_exts
        .iter()
        .chain(ext_policy.inc_exts.iter())
        .any(|allowed| allowed.eq_ignore_ascii_case(ext))
}

fn run_one(
    cli: &Cli,
    asm_name: &str,
    input_base: &str,
    config: &cli::CliConfig,
) -> Result<AsmRunReport, AsmRunError> {
    let root_path = Path::new(asm_name);
    let (root_lines, root_dependency_files) = expand_source_file_with_dependencies(
        root_path,
        &config.defines,
        &config.include_paths,
        config.pp_macro_depth,
    )?;
    let root_module_id = root_module_id_from_lines(root_path, &root_lines)?;
    let graph = load_module_graph(
        root_path,
        root_lines,
        &config.defines,
        &config.include_paths,
        &config.module_paths,
        config.pp_macro_depth,
    )?;
    let source_map = graph.source_map;
    let expanded_lines = Arc::new(graph.lines);
    let mut dependency_files: HashSet<PathBuf> = root_dependency_files.into_iter().collect();
    for path in graph.dependency_files {
        dependency_files.insert(path);
    }

    let mut assembler = Assembler::new();
    if let Some(cpu_name) = config.cpu_override.as_deref() {
        let resolved = assembler
            .registry
            .resolve_cpu_name(cpu_name)
            .ok_or_else(|| {
                let known = assembler.registry.cpu_name_list().join(", ");
                AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        &format!("Unknown CPU: {cpu_name}. Known CPUs: {known}"),
                        None,
                    ),
                    Vec::new(),
                    expanded_lines.clone(),
                )
            })?;
        assembler.cpu = resolved;
    }
    assembler.root_metadata.root_module_id = Some(root_module_id);
    assembler.module_macro_names = graph.module_macro_names;
    let remap_diags = |mut diagnostics: Vec<Diagnostic>| {
        remap_diagnostics_with_source_map(&mut diagnostics, &source_map);
        diagnostics
    };
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&expanded_lines);

    let output_config = assembler
        .root_metadata
        .output_config_for_cpu(assembler.cpu().as_str());
    let metadata_output = output_config.name.as_deref();
    let meta_outputs_requested = output_config.list_name.is_some()
        || output_config.hex_name.is_some()
        || !output_config.bin_specs.is_empty();
    let effective_default_outputs = config.default_outputs && !meta_outputs_requested;
    if pass1.errors == 0
        && effective_default_outputs
        && metadata_output.is_none()
        && cli.outfile.is_none()
    {
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
    if pass1.errors == 0 && config.go_addr.is_some() && hex_path.is_none() {
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

    let mut dependency_targets = Vec::new();
    if let Some(path) = &list_path {
        dependency_targets.push(path.clone());
    }
    if let Some(path) = &hex_path {
        dependency_targets.push(path.clone());
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
    let mut listing = ListingWriter::new_with_options(
        &mut *list_output,
        config.debug_conditionals,
        config.tab_size,
    );
    let header_title = format!("opForge Assembler v{VERSION}");
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
                remap_diags(assembler.take_diagnostics()),
                expanded_lines.clone(),
            ))
        }
    };
    let generated_output = assembler.image().entries().map_err(|err| {
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            remap_diags(assembler.take_diagnostics()),
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
            remap_diags(assembler.take_diagnostics()),
            expanded_lines.clone(),
        ));
    }

    if pass1.errors > 0 || pass2.errors > 0 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Assembler,
                "Errors detected in source. No hex file created.",
                None,
            ),
            remap_diags(assembler.take_diagnostics()),
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
                remap_diags(assembler.take_diagnostics()),
                expanded_lines.clone(),
            )
        })?;
        if let Err(err) = assembler
            .image()
            .write_hex_file(&mut hex_file, config.go_addr.as_deref())
        {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                remap_diags(assembler.take_diagnostics()),
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
                            remap_diags(assembler.take_diagnostics()),
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
        dependency_targets.push(bin_name.clone());
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
                    remap_diags(assembler.take_diagnostics()),
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
                    remap_diags(assembler.take_diagnostics()),
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
            remap_diags(assembler.take_diagnostics()),
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
            remap_diags(assembler.take_diagnostics()),
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
            remap_diags(assembler.take_diagnostics()),
            expanded_lines.clone(),
        ));
    }

    if let Some(path) = &config.labels_file {
        emit_labels_file(
            path,
            config.label_output_format,
            config.output_format,
            assembler.symbols(),
            expanded_lines.clone(),
        )?;
    }

    if let Some(policy) = &config.dependency_output {
        emit_dependency_file(
            policy,
            config.output_format,
            &dependency_targets,
            dependency_files.into_iter().collect(),
            expanded_lines.clone(),
        )?;
    }

    Ok(AsmRunReport::new(
        remap_diags(assembler.take_diagnostics()),
        expanded_lines,
    ))
}
