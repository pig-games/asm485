use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;

use crate::core::assembler::error::{AsmError, AsmErrorKind, AsmRunError};
use crate::core::symbol_table::{SymbolTable, SymbolVisibility};

use super::{
    cli, format_addr, ExportSectionsDirective, ExportSectionsInclude, LinkerOutputDirective,
    LinkerOutputFormat, MapFileDirective, MapSymbolsMode, OutputFormat, RegionState, SectionKind,
    SectionState,
};

#[derive(Debug, Clone)]
struct ResolvedLinkerSection {
    name: String,
    base: u32,
    bytes: Vec<u8>,
}

pub(super) fn emit_labels_file(
    path: &Path,
    format: cli::LabelOutputFormat,
    output_format: cli::OutputFormat,
    symbols: &SymbolTable,
    source_lines: Arc<Vec<String>>,
) -> Result<(), AsmRunError> {
    let mut entries = symbols.entries().to_vec();
    entries.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });

    let output =
        if output_format == cli::OutputFormat::Json && format == cli::LabelOutputFormat::Default {
            let labels: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|entry| {
                    json!({
                        "name": entry.name,
                        "address": format_addr(entry.val),
                        "value": entry.val,
                    })
                })
                .collect();
            json!({ "labels": labels }).to_string()
        } else {
            let mut output = String::new();
            for entry in entries {
                let address = format_addr(entry.val);
                match format {
                    cli::LabelOutputFormat::Default => {
                        output.push_str(&format!("{} = ${address}\n", entry.name));
                    }
                    cli::LabelOutputFormat::Vice => {
                        output.push_str(&format!("al C:${address} .{}\n", entry.name));
                    }
                    cli::LabelOutputFormat::Ctags => {
                        output.push_str(&format!(
                            "{}\tlabels\t/^{}$/;\"\tv\n",
                            entry.name, entry.name
                        ));
                    }
                }
            }
            output
        };

    fs::write(path, output).map_err(|err| {
        AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Io,
                &format!("Error writing labels file: {err}"),
                Some(path.to_string_lossy().as_ref()),
            ),
            Vec::new(),
            source_lines,
        )
    })
}

fn make_escape_path(path: &str) -> String {
    path.replace(' ', "\\ ")
}

pub(super) fn emit_dependency_file(
    policy: &cli::DependencyOutputPolicy,
    output_format: cli::OutputFormat,
    targets: &[String],
    dependencies: Vec<PathBuf>,
    source_lines: Arc<Vec<String>>,
) -> Result<(), AsmRunError> {
    let mut targets: Vec<String> = targets
        .iter()
        .filter(|target| !target.is_empty())
        .map(|target| make_escape_path(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Ok(());
    }

    let mut dependencies: Vec<String> = dependencies
        .into_iter()
        .map(|path| make_escape_path(path.to_string_lossy().as_ref()))
        .collect();
    dependencies.sort();
    dependencies.dedup();

    let body = if output_format == OutputFormat::Json {
        json!({
            "targets": targets,
            "dependencies": dependencies,
            "make_phony": policy.make_phony,
            "phony_targets": if policy.make_phony { dependencies.clone() } else { Vec::new() },
        })
        .to_string()
            + "\n"
    } else {
        let mut body = String::new();
        body.push_str(&format!(
            "{}: {}\n",
            targets.join(" "),
            dependencies.join(" ")
        ));
        if policy.make_phony {
            for dependency in &dependencies {
                body.push_str(&format!("{dependency}:\n"));
            }
        }
        body
    };

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if policy.append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    let mut file = options.open(&policy.path).map_err(|err| {
        AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Io,
                &format!("Error opening dependency file: {err}"),
                Some(policy.path.to_string_lossy().as_ref()),
            ),
            Vec::new(),
            source_lines.clone(),
        )
    })?;
    file.write_all(body.as_bytes()).map_err(|err| {
        AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Io,
                &format!("Error writing dependency file: {err}"),
                Some(policy.path.to_string_lossy().as_ref()),
            ),
            Vec::new(),
            source_lines,
        )
    })?;

    Ok(())
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

pub(super) fn build_linker_output_payload(
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

pub(super) fn emit_linker_outputs(
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

pub(super) fn build_export_sections_payloads(
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

pub(super) fn emit_export_sections(
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

pub(super) fn build_mapfile_text(
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

pub(super) fn emit_mapfiles(
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
