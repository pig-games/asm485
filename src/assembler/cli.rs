// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Command-line interface parsing and argument validation.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser, ValueEnum};

use crate::core::assembler::error::{AsmError, AsmErrorKind, AsmRunError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const LONG_ABOUT: &str =
    "Multi-CPU assembler supporting Intel 8080/8085, Zilog Z80, MOS 6502, and WDC 65C02.

Outputs are opt-in: specify at least one of -l/--list, -x/--hex, or -b/--bin.
If no outputs are specified for a single input, the assembler defaults to list+hex
when a root-module output name (or -o) is available.
Use -o/--outfile to set the output base name when filenames are omitted.
For -b, ranges are optional: ssss:eeee (4-8 hex digits each).
If a range is omitted, the binary spans the emitted output.
With multiple -b ranges and no filenames, outputs are named <base>-ssss.bin.
With multiple inputs, -o must be a directory and explicit output filenames are not allowed.";

#[derive(Parser, Debug)]
#[command(
    name = "opForge",
    version = VERSION,
    about = "Multi-CPU assembler (8080/8085/Z80/6502/65C02) with expressions, directives and macro support",
    long_about = LONG_ABOUT
)]
pub struct Cli {
    #[arg(
        long = "format",
        value_enum,
        default_value_t = OutputFormat::Text,
        long_help = "Select global CLI output format. text is default; json enables machine-readable output where supported."
    )]
    pub format: OutputFormat,
    #[arg(
        short = 'q',
        long = "quiet",
        action = ArgAction::SetTrue,
        long_help = "Suppress diagnostic output for successful assembly runs. Errors are still reported unless --no-error is set."
    )]
    pub quiet: bool,
    #[arg(
        short = 'E',
        long = "error",
        value_name = "FILE",
        long_help = "Write diagnostics to FILE instead of stderr."
    )]
    pub error_file: Option<PathBuf>,
    #[arg(
        long = "error-append",
        action = ArgAction::SetTrue,
        requires = "error_file",
        long_help = "Append diagnostics to --error FILE instead of truncating it."
    )]
    pub error_append: bool,
    #[arg(
        long = "no-error",
        action = ArgAction::SetTrue,
        conflicts_with_all = ["error_file", "error_append"],
        long_help = "Disable all diagnostic output routing."
    )]
    pub no_error: bool,
    #[arg(
        short = 'w',
        long = "no-warn",
        action = ArgAction::SetTrue,
        conflicts_with_all = ["warn_all", "warn_error"],
        long_help = "Suppress warning diagnostics."
    )]
    pub no_warn: bool,
    #[arg(
        long = "Wall",
        action = ArgAction::SetTrue,
        conflicts_with = "no_warn",
        long_help = "Enable all warning classes (reserved for future warning groups)."
    )]
    pub warn_all: bool,
    #[arg(
        long = "Werror",
        action = ArgAction::SetTrue,
        conflicts_with = "no_warn",
        long_help = "Treat warnings as errors (non-zero exit status)."
    )]
    pub warn_error: bool,
    #[arg(
        long = "print-capabilities",
        action = ArgAction::SetTrue,
        long_help = "Print deterministic capability metadata and exit."
    )]
    pub print_capabilities: bool,
    #[arg(
        long = "print-cpusupport",
        action = ArgAction::SetTrue,
        long_help = "Print deterministic CPU support metadata and exit."
    )]
    pub print_cpusupport: bool,
    #[arg(
        long = "cpu",
        value_name = "ID",
        long_help = "Select initial CPU profile before parsing source directives. In-source .cpu directives can still override later."
    )]
    pub cpu: Option<String>,
    #[arg(
        short = 'l',
        long = "list",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        long_help = "Emit a listing file. FILE is optional; when omitted, the output base is used and a .lst extension is added."
    )]
    pub list_name: Option<String>,
    #[arg(
        short = 'x',
        long = "hex",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        long_help = "Emit an Intel Hex file. FILE is optional; when omitted, the output base is used and a .hex extension is added."
    )]
    pub hex_name: Option<String>,
    #[arg(
        short = 'o',
        long = "outfile",
        value_name = "BASE",
        long_help = "Output filename base when -l/-x omit filenames, and for -b when a filename is omitted. Defaults to the input base. With multiple inputs, BASE must be a directory."
    )]
    pub outfile: Option<String>,
    #[arg(
        long = "dependencies",
        value_name = "FILE",
        long_help = "Write Makefile-compatible dependency rules to FILE."
    )]
    pub dependencies_file: Option<PathBuf>,
    #[arg(
        long = "labels",
        value_name = "FILE",
        long_help = "Write assembled symbol labels to FILE."
    )]
    pub labels_file: Option<PathBuf>,
    #[arg(
        long = "vice-labels",
        action = ArgAction::SetTrue,
        requires = "labels_file",
        conflicts_with = "ctags_labels",
        long_help = "Write --labels output in VICE-compatible format."
    )]
    pub vice_labels: bool,
    #[arg(
        long = "ctags-labels",
        action = ArgAction::SetTrue,
        requires = "labels_file",
        conflicts_with = "vice_labels",
        long_help = "Write --labels output in ctags-compatible format."
    )]
    pub ctags_labels: bool,
    #[arg(
        long = "dependencies-append",
        action = ArgAction::SetTrue,
        requires = "dependencies_file",
        long_help = "Append dependency rules to --dependencies FILE instead of truncating it."
    )]
    pub dependencies_append: bool,
    #[arg(
        long = "make-phony",
        action = ArgAction::SetTrue,
        requires = "dependencies_file",
        long_help = "Emit phony targets for each dependency path in the generated dependency file."
    )]
    pub make_phony: bool,
    #[arg(
        short = 'b',
        long = "bin",
        value_name = "[FILE:]ssss:eeee|FILE",
        num_args = 0..=1,
        default_missing_value = "",
        action = ArgAction::Append,
        long_help = "Emit a binary image file (repeatable). Ranges are optional: ssss:eeee (4-8 hex digits each). Use ssss:eeee to use the output base, or FILE:ssss:eeee to override the filename. If FILE has no extension, .bin is added. If no range is supplied, the binary spans the emitted output. If multiple -b ranges are provided without filenames, outputs are named <base>-ssss.bin."
    )]
    pub bin_outputs: Vec<String>,
    #[arg(
        short = 'f',
        long = "fill",
        value_name = "hh",
        long_help = "Fill byte for binary output (2 hex digits). Defaults to FF."
    )]
    pub fill_byte: Option<String>,
    #[arg(
        short = 'g',
        long = "go",
        value_name = "aaaa",
        long_help = "Set execution start address (4-8 hex digits). Adds a Start Address record to hex output. Requires hex output."
    )]
    pub go_addr: Option<String>,
    #[arg(
        short = 'c',
        long = "cond-debug",
        action = ArgAction::SetTrue,
        long_help = "Append conditional assembly state to listing lines."
    )]
    pub debug_conditionals: bool,
    #[arg(
        long = "line-numbers",
        action = ArgAction::SetTrue,
        long_help = "Compatibility flag for listing output line-number column (enabled by default)."
    )]
    pub line_numbers: bool,
    #[arg(
        long = "tab-size",
        value_name = "N",
        long_help = "Expand tab characters in listing source text using N spaces."
    )]
    pub tab_size: Option<usize>,
    #[arg(
        long = "verbose-list",
        action = ArgAction::SetTrue,
        long_help = "Enable verbose listing mode (compatibility flag; reserved for expanded listing sections)."
    )]
    pub verbose_list: bool,
    #[arg(
        short = 'D',
        long = "define",
        value_name = "NAME[=VAL]",
        action = ArgAction::Append,
        long_help = "Predefine a macro (repeatable). If VAL is omitted, defaults to 1."
    )]
    pub defines: Vec<String>,
    #[arg(
        short = 'i',
        long = "infile",
        value_name = "FILE|FOLDER",
        action = ArgAction::Append,
        long_help = "Input assembly file or folder (repeatable). Files must end with .asm. Folder inputs must contain exactly one main.* root module."
    )]
    pub infiles: Vec<PathBuf>,
    #[arg(
        value_name = "INPUT",
        action = ArgAction::Append,
        long_help = "Optional migration-friendly positional input. Exactly one positional INPUT is accepted and treated like -i INPUT. Multiple positional inputs require explicit -i/--infile."
    )]
    pub positional_inputs: Vec<PathBuf>,
    #[arg(
        short = 'I',
        long = "include-path",
        value_name = "DIR",
        action = ArgAction::Append,
        long_help = "Additional include search root (repeatable). Include resolution order is: including file directory, then include roots in command-line order."
    )]
    pub include_paths: Vec<PathBuf>,
    #[arg(
        short = 'M',
        long = "module-path",
        value_name = "DIR",
        action = ArgAction::Append,
        long_help = "Additional module search root (repeatable). Module roots are searched in this order: input root directory, then module roots in command-line order."
    )]
    pub module_paths: Vec<PathBuf>,
    #[arg(
        long = "pp-macro-depth",
        value_name = "N",
        default_value_t = 64,
        long_help = "Maximum preprocessor macro expansion depth. Defaults to 64."
    )]
    pub pp_macro_depth: usize,
    #[arg(
        long = "input-asm-ext",
        value_name = "EXT",
        action = ArgAction::Append,
        long_help = "Additional accepted source-file extension for direct file inputs (repeatable). Defaults to asm."
    )]
    pub input_asm_exts: Vec<String>,
    #[arg(
        long = "input-inc-ext",
        value_name = "EXT",
        action = ArgAction::Append,
        long_help = "Additional accepted root-module extension for folder inputs (repeatable). Defaults to inc."
    )]
    pub input_inc_exts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BinRange {
    pub start_str: String,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone)]
pub struct BinOutputSpec {
    pub name: Option<String>,
    pub range: Option<BinRange>,
}

#[derive(Debug, Clone)]
pub enum DiagnosticsSinkConfig {
    Stderr,
    File { path: PathBuf, append: bool },
    Disabled,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WarningPolicy {
    pub emit_warnings: bool,
    pub enable_all_warnings: bool,
    pub treat_warnings_as_errors: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InputExtensionPolicy {
    pub asm_exts: Vec<String>,
    pub inc_exts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DependencyOutputPolicy {
    pub path: PathBuf,
    pub append: bool,
    pub make_phony: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LabelOutputFormat {
    #[default]
    Default,
    Vice,
    Ctags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

pub fn is_valid_hex_4(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_hex_4_to_8(s: &str) -> bool {
    (4..=8).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_hex_2(s: &str) -> bool {
    s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_bin_range(s: &str) -> bool {
    let Some((start, end)) = s.split_once(':') else {
        return false;
    };
    if end.contains(':') {
        return false;
    }
    is_valid_hex_4_to_8(start) && is_valid_hex_4_to_8(end)
}

pub fn parse_bin_output_arg(arg: &str) -> Result<BinOutputSpec, &'static str> {
    const RANGE_ERR: &str =
        "Invalid -b/--bin range; must be ssss:eeee (4-8 hex digits, start <= end)";

    if arg.is_empty() {
        return Ok(BinOutputSpec {
            name: None,
            range: None,
        });
    }

    if let Some(range) = parse_bin_range_str(arg) {
        return Ok(BinOutputSpec {
            name: None,
            range: Some(range),
        });
    }

    if let Some((name_part, start, end)) = split_range_suffix(arg) {
        let range = parse_bin_range_parts(start, end).ok_or(RANGE_ERR)?;
        let name = if name_part.is_empty() {
            None
        } else {
            Some(name_part.to_string())
        };
        return Ok(BinOutputSpec {
            name,
            range: Some(range),
        });
    }

    if !arg.contains(':') {
        return Ok(BinOutputSpec {
            name: Some(arg.to_string()),
            range: None,
        });
    }

    if is_valid_bin_range(arg) {
        return Err(RANGE_ERR);
    }

    Err("Invalid -b/--bin argument; use ssss:eeee, name:ssss:eeee, or name only (4-8 hex digits)")
}

fn split_range_suffix(s: &str) -> Option<(&str, &str, &str)> {
    let mut parts = s.rsplitn(3, ':');
    let end = parts.next()?;
    let start = parts.next()?;
    let name = parts.next()?;
    if is_valid_hex_4_to_8(start) && is_valid_hex_4_to_8(end) {
        Some((name, start, end))
    } else {
        None
    }
}

fn parse_bin_range_parts(start: &str, end: &str) -> Option<BinRange> {
    if !is_valid_hex_4_to_8(start) || !is_valid_hex_4_to_8(end) {
        return None;
    }
    let start_str = start.to_string();
    let end_str = end.to_string();
    let start = match u32::from_str_radix(&start_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let end = match u32::from_str_radix(&end_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if start > end {
        return None;
    }
    Some(BinRange {
        start_str,
        start,
        end,
    })
}

pub fn parse_bin_range_str(s: &str) -> Option<BinRange> {
    if !is_valid_bin_range(s) {
        return None;
    }
    let (start_text, end_text) = s.split_once(':')?;
    let start_str = start_text.to_string();
    let end_str = end_text.to_string();
    let start = match u32::from_str_radix(&start_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let end = match u32::from_str_radix(&end_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    if start > end {
        return None;
    }
    Some(BinRange {
        start_str,
        start,
        end,
    })
}

pub fn resolve_output_path(base: &str, name: Option<String>, extension: &str) -> Option<String> {
    let name = name?;
    if name.is_empty() {
        return Some(format!("{base}.{extension}"));
    }
    let mut path = PathBuf::from(&name);
    if path.extension().is_none() {
        path = PathBuf::from(format!("{name}.{extension}"));
    }
    Some(path.to_string_lossy().to_string())
}

pub fn resolve_bin_path(
    base: &str,
    name: Option<&str>,
    range: Option<&BinRange>,
    bin_count: usize,
    index: usize,
) -> String {
    let name = match name {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            if bin_count == 1 {
                base.to_string()
            } else if let Some(range) = range {
                format!("{base}-{}", range.start_str)
            } else {
                format!("{base}-{}", index + 1)
            }
        }
    };
    let path = PathBuf::from(&name);
    if path.extension().is_none() {
        return format!("{name}.bin");
    }
    name
}

pub fn input_base_from_path(
    path: &Path,
    ext_policy: &InputExtensionPolicy,
) -> Result<(String, String), AsmRunError> {
    let file_name = match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name,
        None => {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Cli, "Invalid input file name", None),
                Vec::new(),
                Vec::new(),
            ))
        }
    };

    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext_policy
        .asm_exts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(ext))
    {
        if path.is_dir() {
            return Err(AsmRunError::new(
                AsmError::new(
                    AsmErrorKind::Cli,
                    "Input path has an accepted source extension but is a folder",
                    None,
                ),
                Vec::new(),
                Vec::new(),
            ));
        }
        if !path.is_file() {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Cli, "Input source file not found", None),
                Vec::new(),
                Vec::new(),
            ));
        }
        let asm_name = path.to_string_lossy().to_string();
        let base = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file_name);
        return Ok((asm_name, base.to_string()));
    }

    if path.is_dir() {
        return resolve_root_module_from_dir(path, ext_policy);
    }

    if path.is_file() || !path.exists() {
        let accepted = ext_policy
            .asm_exts
            .iter()
            .map(|ext| format!(".{ext}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                &format!("Input file must use one of these source extensions: {accepted}"),
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    Err(AsmRunError::new(
        AsmError::new(AsmErrorKind::Cli, "Invalid input path", None),
        Vec::new(),
        Vec::new(),
    ))
}

fn resolve_root_module_from_dir(
    path: &Path,
    ext_policy: &InputExtensionPolicy,
) -> Result<(String, String), AsmRunError> {
    let dir_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Cli, "Invalid input folder name", None),
                Vec::new(),
                Vec::new(),
            )
        })?
        .to_string();

    let mut matches = Vec::new();
    let entries = fs::read_dir(path).map_err(|err| {
        AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, "Error reading input folder", None),
            vec![],
            vec![err.to_string()],
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, "Error reading input folder", None),
                vec![],
                vec![err.to_string()],
            )
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !stem.eq_ignore_ascii_case("main") {
            continue;
        }
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let is_allowed = ext_policy
            .asm_exts
            .iter()
            .chain(ext_policy.inc_exts.iter())
            .any(|allowed| allowed.eq_ignore_ascii_case(ext));
        if !is_allowed {
            continue;
        }
        matches.push(path);
    }

    if matches.is_empty() {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "Input folder must contain exactly one main.* root module",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }
    if matches.len() > 1 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "Input folder contains multiple main.* root modules",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    let asm_name = matches[0].to_string_lossy().to_string();
    Ok((asm_name, dir_name))
}

fn normalize_extension_list(
    input: &[String],
    default: &[&str],
    flag_name: &str,
) -> Result<Vec<String>, AsmRunError> {
    let raw_values: Vec<String> = if input.is_empty() {
        default.iter().map(|value| value.to_string()).collect()
    } else {
        input.to_vec()
    };

    let mut normalized = Vec::new();
    for value in raw_values {
        let value = value.trim().trim_start_matches('.').to_ascii_lowercase();
        if value.is_empty() {
            return Err(AsmRunError::new(
                AsmError::new(
                    AsmErrorKind::Cli,
                    &format!("{flag_name} expects a non-empty extension"),
                    None,
                ),
                Vec::new(),
                Vec::new(),
            ));
        }
        if !normalized.iter().any(|ext: &String| ext == &value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn cli_error(message: impl Into<String>) -> AsmRunError {
    AsmRunError::new(
        AsmError::new(AsmErrorKind::Cli, &message.into(), None),
        Vec::new(),
        Vec::new(),
    )
}

fn parse_env_bool(var_name: &str) -> Result<Option<bool>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(None);
    };
    let value = raw.to_string_lossy().trim().to_ascii_lowercase();
    let parsed = match value.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        "" => None,
        _ => {
            return Err(cli_error(format!(
                "Invalid boolean value for {var_name}: {value}"
            )))
        }
    };
    Ok(parsed)
}

fn parse_env_path(var_name: &str) -> Result<Option<PathBuf>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(None);
    };
    let value = raw.to_string_lossy().trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(value)))
}

fn parse_env_path_list(var_name: &str) -> Result<Vec<PathBuf>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(Vec::new());
    };
    let values: Vec<PathBuf> = env::split_paths(&raw)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    Ok(values)
}

fn parse_env_csv_list(var_name: &str) -> Result<Vec<String>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(Vec::new());
    };
    let value = raw.to_string_lossy();
    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn parse_env_usize(var_name: &str) -> Result<Option<usize>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(None);
    };
    let value = raw.to_string_lossy().trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<usize>()
        .map(Some)
        .map_err(|_| cli_error(format!("Invalid integer value for {var_name}: {value}")))
}

fn parse_env_string(var_name: &str) -> Result<Option<String>, AsmRunError> {
    let Some(raw) = env::var_os(var_name) else {
        return Ok(None);
    };
    let value = raw.to_string_lossy().trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value))
}

/// Validate CLI arguments and return parsed configuration.
pub fn validate_cli(cli: &Cli) -> Result<CliConfig, AsmRunError> {
    let env_cpu = parse_env_string("OPFORGE_CPU")?;
    let env_include_paths = parse_env_path_list("OPFORGE_INCLUDE_PATHS")?;
    let env_module_paths = parse_env_path_list("OPFORGE_MODULE_PATHS")?;
    let env_input_asm_exts = parse_env_csv_list("OPFORGE_INPUT_ASM_EXTS")?;
    let env_input_inc_exts = parse_env_csv_list("OPFORGE_INPUT_INC_EXTS")?;
    let env_defines = parse_env_csv_list("OPFORGE_DEFINES")?;

    let env_quiet = parse_env_bool("OPFORGE_QUIET")?;
    let env_no_warn = parse_env_bool("OPFORGE_NO_WARN")?;
    let env_warn_all = parse_env_bool("OPFORGE_WALL")?;
    let env_warn_error = parse_env_bool("OPFORGE_WERROR")?;

    let env_error_file = parse_env_path("OPFORGE_ERROR_FILE")?;
    let env_error_append = parse_env_bool("OPFORGE_ERROR_APPEND")?;
    let env_no_error = parse_env_bool("OPFORGE_NO_ERROR")?;

    let env_dependencies_file = parse_env_path("OPFORGE_DEPENDENCIES_FILE")?;
    let env_dependencies_append = parse_env_bool("OPFORGE_DEPENDENCIES_APPEND")?;
    let env_make_phony = parse_env_bool("OPFORGE_MAKE_PHONY")?;

    let env_labels_file = parse_env_path("OPFORGE_LABELS_FILE")?;
    let env_labels_format = parse_env_string("OPFORGE_LABELS_FORMAT")?;

    let env_tab_size = parse_env_usize("OPFORGE_TAB_SIZE")?;
    let env_line_numbers = parse_env_bool("OPFORGE_LINE_NUMBERS")?;
    let env_verbose_list = parse_env_bool("OPFORGE_VERBOSE_LIST")?;
    let env_cond_debug = parse_env_bool("OPFORGE_COND_DEBUG")?;

    let env_fill_byte = parse_env_string("OPFORGE_FILL_BYTE")?;
    let env_pp_macro_depth = parse_env_usize("OPFORGE_PP_MACRO_DEPTH")?;

    let mut effective_asm_exts = env_input_asm_exts;
    effective_asm_exts.extend(cli.input_asm_exts.clone());
    let mut effective_inc_exts = env_input_inc_exts;
    effective_inc_exts.extend(cli.input_inc_exts.clone());

    let mut effective_include_paths = env_include_paths;
    effective_include_paths.extend(cli.include_paths.clone());
    let mut effective_module_paths = env_module_paths;
    effective_module_paths.extend(cli.module_paths.clone());

    let mut effective_defines = env_defines;
    effective_defines.extend(cli.defines.clone());

    let effective_cpu = cli.cpu.clone().or(env_cpu);

    let effective_quiet = if cli.quiet {
        true
    } else {
        env_quiet.unwrap_or(false)
    };

    let effective_no_warn = if cli.no_warn {
        true
    } else if cli.warn_all || cli.warn_error {
        false
    } else {
        env_no_warn.unwrap_or(false)
    };

    let effective_warn_all = if cli.warn_all {
        true
    } else if effective_no_warn {
        false
    } else {
        env_warn_all.unwrap_or(false)
    };

    let effective_warn_error = if cli.warn_error {
        true
    } else if effective_no_warn {
        false
    } else {
        env_warn_error.unwrap_or(false)
    };

    let effective_error_file = if cli.error_file.is_some() {
        cli.error_file.clone()
    } else {
        env_error_file
    };

    let effective_error_append = if cli.error_append {
        true
    } else {
        env_error_append.unwrap_or(false)
    };

    let effective_no_error = if cli.no_error {
        true
    } else if cli.error_file.is_some() {
        false
    } else {
        env_no_error.unwrap_or(false)
    };

    let effective_dependencies_file = if cli.dependencies_file.is_some() {
        cli.dependencies_file.clone()
    } else {
        env_dependencies_file
    };

    let effective_dependencies_append = if cli.dependencies_append {
        true
    } else {
        env_dependencies_append.unwrap_or(false)
    };

    let effective_make_phony = if cli.make_phony {
        true
    } else {
        env_make_phony.unwrap_or(false)
    };

    let effective_labels_file = if cli.labels_file.is_some() {
        cli.labels_file.clone()
    } else {
        env_labels_file
    };

    let env_label_output_format = match env_labels_format
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("default") | None => LabelOutputFormat::Default,
        Some("vice") => LabelOutputFormat::Vice,
        Some("ctags") => LabelOutputFormat::Ctags,
        Some(other) => {
            return Err(cli_error(format!(
            "Invalid OPFORGE_LABELS_FORMAT value: {other}. Expected one of: default, vice, ctags"
        )))
        }
    };

    let effective_label_output_format = if cli.vice_labels {
        LabelOutputFormat::Vice
    } else if cli.ctags_labels {
        LabelOutputFormat::Ctags
    } else {
        env_label_output_format
    };

    let effective_tab_size = if cli.tab_size.is_some() {
        cli.tab_size
    } else {
        env_tab_size
    };

    let effective_line_numbers = if cli.line_numbers {
        true
    } else {
        env_line_numbers.unwrap_or(true)
    };

    let effective_verbose_list = if cli.verbose_list {
        true
    } else {
        env_verbose_list.unwrap_or(false)
    };

    let effective_cond_debug = if cli.debug_conditionals {
        true
    } else {
        env_cond_debug.unwrap_or(false)
    };

    let effective_fill_byte = if cli.fill_byte.is_some() {
        cli.fill_byte.clone()
    } else {
        env_fill_byte
    };

    let effective_pp_macro_depth = if cli.pp_macro_depth != 64 {
        cli.pp_macro_depth
    } else {
        env_pp_macro_depth.unwrap_or(cli.pp_macro_depth)
    };

    let input_extensions = InputExtensionPolicy {
        asm_exts: normalize_extension_list(&effective_asm_exts, &["asm"], "--input-asm-ext")?,
        inc_exts: normalize_extension_list(&effective_inc_exts, &["inc"], "--input-inc-ext")?,
    };

    let input_paths = if !cli.infiles.is_empty() {
        if !cli.positional_inputs.is_empty() {
            return Err(AsmRunError::new(
                AsmError::new(
                    AsmErrorKind::Cli,
                    "Do not mix positional input with -i/--infile; use one style",
                    None,
                ),
                Vec::new(),
                Vec::new(),
            ));
        }
        cli.infiles.clone()
    } else if cli.positional_inputs.len() == 1 {
        cli.positional_inputs.clone()
    } else if cli.positional_inputs.len() > 1 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "Multiple positional inputs are not supported; use repeatable -i/--infile",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    } else {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "No input files specified. Use -i/--infile",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    };

    let list_requested = cli.list_name.is_some();
    let hex_requested = cli.hex_name.is_some();
    let bin_requested = !cli.bin_outputs.is_empty();

    let default_outputs = !list_requested && !hex_requested && !bin_requested;
    if default_outputs && input_paths.len() > 1 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "No outputs selected. Use -l/--list, -x/--hex, or -b/--bin with multiple inputs",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    if input_paths.len() > 1 {
        if let Some(list_name) = cli.list_name.as_deref() {
            if !list_name.is_empty() {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "Explicit -l/--list filenames are not allowed with multiple inputs",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
        }
        if let Some(hex_name) = cli.hex_name.as_deref() {
            if !hex_name.is_empty() {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "Explicit -x/--hex filenames are not allowed with multiple inputs",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
        }
    }

    let go_addr = match cli.go_addr.as_deref() {
        Some(go) => {
            if !is_valid_hex_4_to_8(go) {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "Invalid -g/--go address; must be 4-8 hex digits",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            Some(go.to_string())
        }
        None => None,
    };

    let mut bin_specs = Vec::new();
    for arg in &cli.bin_outputs {
        let spec = parse_bin_output_arg(arg).map_err(|msg| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Cli, msg, None),
                Vec::new(),
                Vec::new(),
            )
        })?;
        bin_specs.push(spec);
    }
    if input_paths.len() > 1 && bin_specs.iter().any(|spec| spec.name.is_some()) {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "Explicit -b/--bin filenames are not allowed with multiple inputs",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    let fill_byte_set = effective_fill_byte.is_some();
    let fill_byte = match effective_fill_byte.as_deref() {
        Some(fill) => {
            if !is_valid_hex_2(fill) {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "Invalid -f/--fill byte; must be 2 hex digits",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            match u8::from_str_radix(fill, 16) {
                Ok(b) => b,
                Err(_) => {
                    return Err(AsmRunError::new(
                        AsmError::new(
                            AsmErrorKind::Cli,
                            "Invalid -f/--fill byte; must be 2 hex digits",
                            None,
                        ),
                        Vec::new(),
                        Vec::new(),
                    ))
                }
            }
        }
        None => 0xff,
    };

    let out_dir = if input_paths.len() > 1 {
        if let Some(out) = cli.outfile.as_deref() {
            let out_path = PathBuf::from(out);
            if out_path.exists() && !out_path.is_dir() {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "-o/--outfile must be a directory when multiple inputs are provided",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            if let Err(err) = fs::create_dir_all(&out_path) {
                return Err(AsmRunError::new(
                    AsmError::new(AsmErrorKind::Io, &err.to_string(), Some(out)),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            Some(out_path)
        } else {
            None
        }
    } else {
        None
    };

    if effective_pp_macro_depth == 0 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "--pp-macro-depth must be at least 1",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    if matches!(effective_tab_size, Some(0)) {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Cli, "--tab-size must be at least 1", None),
            Vec::new(),
            Vec::new(),
        ));
    }

    if (effective_dependencies_append || effective_make_phony)
        && effective_dependencies_file.is_none()
    {
        return Err(cli_error(
            "--dependencies-append/--make-phony requires --dependencies",
        ));
    }

    if effective_label_output_format != LabelOutputFormat::Default
        && effective_labels_file.is_none()
    {
        return Err(cli_error("--vice-labels/--ctags-labels requires --labels"));
    }

    Ok(CliConfig {
        input_paths,
        input_extensions,
        cpu_override: effective_cpu,
        go_addr,
        bin_specs,
        fill_byte,
        fill_byte_set,
        out_dir,
        defines: effective_defines,
        include_paths: effective_include_paths,
        module_paths: effective_module_paths,
        quiet: effective_quiet,
        line_numbers: effective_line_numbers,
        tab_size: effective_tab_size,
        verbose_list: effective_verbose_list,
        debug_conditionals: effective_cond_debug,
        output_format: cli.format,
        diagnostics_sink: if effective_no_error {
            DiagnosticsSinkConfig::Disabled
        } else if let Some(path) = &effective_error_file {
            DiagnosticsSinkConfig::File {
                path: path.clone(),
                append: effective_error_append,
            }
        } else {
            DiagnosticsSinkConfig::Stderr
        },
        warning_policy: WarningPolicy {
            emit_warnings: !effective_no_warn,
            enable_all_warnings: effective_warn_all,
            treat_warnings_as_errors: effective_warn_error,
        },
        labels_file: effective_labels_file,
        label_output_format: effective_label_output_format,
        dependency_output: effective_dependencies_file.as_ref().map(|path| {
            DependencyOutputPolicy {
                path: path.clone(),
                append: effective_dependencies_append,
                make_phony: effective_make_phony,
            }
        }),
        pp_macro_depth: effective_pp_macro_depth,
        default_outputs,
    })
}

/// Validated CLI configuration.
#[derive(Debug)]
pub struct CliConfig {
    pub input_paths: Vec<PathBuf>,
    pub input_extensions: InputExtensionPolicy,
    pub cpu_override: Option<String>,
    pub defines: Vec<String>,
    pub go_addr: Option<String>,
    pub bin_specs: Vec<BinOutputSpec>,
    pub fill_byte: u8,
    pub fill_byte_set: bool,
    pub out_dir: Option<PathBuf>,
    pub include_paths: Vec<PathBuf>,
    pub module_paths: Vec<PathBuf>,
    pub quiet: bool,
    pub line_numbers: bool,
    pub tab_size: Option<usize>,
    pub verbose_list: bool,
    pub debug_conditionals: bool,
    pub output_format: OutputFormat,
    pub diagnostics_sink: DiagnosticsSinkConfig,
    pub warning_policy: WarningPolicy,
    pub labels_file: Option<PathBuf>,
    pub label_output_format: LabelOutputFormat,
    pub dependency_output: Option<DependencyOutputPolicy>,
    pub pp_macro_depth: usize,
    pub default_outputs: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::process;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn range_0000_ffff() -> BinRange {
        parse_bin_range_str("0000:ffff").expect("valid range")
    }

    fn default_input_extensions() -> InputExtensionPolicy {
        InputExtensionPolicy {
            asm_exts: vec!["asm".to_string()],
            inc_exts: vec!["inc".to_string()],
        }
    }

    fn with_env_vars(vars: &[(&str, Option<&str>)], test: impl FnOnce()) {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock env mutex");

        let saved: Vec<(String, Option<OsString>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), env::var_os(key)))
            .collect();

        for (key, value) in vars {
            match value {
                Some(value) => {
                    // SAFETY: tests serialize env access via ENV_LOCK.
                    unsafe { env::set_var(key, value) }
                }
                None => {
                    // SAFETY: tests serialize env access via ENV_LOCK.
                    unsafe { env::remove_var(key) }
                }
            }
        }

        test();

        for (key, value) in saved {
            match value {
                Some(value) => {
                    // SAFETY: tests serialize env access via ENV_LOCK.
                    unsafe { env::set_var(key, value) }
                }
                None => {
                    // SAFETY: tests serialize env access via ENV_LOCK.
                    unsafe { env::remove_var(key) }
                }
            }
        }
    }

    #[test]
    fn cli_parses_outputs_and_inputs() {
        let cli = Cli::parse_from([
            "opForge",
            "--format",
            "json",
            "-i",
            "prog.asm",
            "-I",
            "inc",
            "-M",
            "modules",
            "-q",
            "-E",
            "diag.log",
            "--error-append",
            "--Wall",
            "--cpu",
            "m6502",
            "--labels",
            "symbols.lbl",
            "--dependencies",
            "deps.mk",
            "--dependencies-append",
            "--make-phony",
            "--line-numbers",
            "--tab-size",
            "4",
            "--verbose-list",
            "--pp-macro-depth",
            "80",
            "-l",
            "-x",
            "-b",
            "0000:ffff",
            "-o",
            "out",
            "-f",
            "aa",
        ]);
        assert_eq!(cli.infiles, vec![PathBuf::from("prog.asm")]);
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(cli.include_paths, vec![PathBuf::from("inc")]);
        assert_eq!(cli.module_paths, vec![PathBuf::from("modules")]);
        assert!(cli.quiet);
        assert_eq!(cli.error_file, Some(PathBuf::from("diag.log")));
        assert!(cli.error_append);
        assert!(cli.warn_all);
        assert!(!cli.print_capabilities);
        assert!(!cli.print_cpusupport);
        assert_eq!(cli.cpu.as_deref(), Some("m6502"));
        assert!(cli.line_numbers);
        assert_eq!(cli.tab_size, Some(4));
        assert!(cli.verbose_list);
        assert_eq!(cli.labels_file, Some(PathBuf::from("symbols.lbl")));
        assert_eq!(cli.dependencies_file, Some(PathBuf::from("deps.mk")));
        assert!(cli.dependencies_append);
        assert!(cli.make_phony);
        assert_eq!(cli.list_name, Some(String::new()));
        assert_eq!(cli.hex_name, Some(String::new()));
        assert_eq!(cli.outfile, Some("out".to_string()));
        assert_eq!(cli.bin_outputs, vec!["0000:ffff".to_string()]);
        assert_eq!(cli.fill_byte, Some("aa".to_string()));
        assert_eq!(cli.pp_macro_depth, 80);
    }

    #[test]
    fn cli_defaults_pp_macro_depth() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l"]);
        assert_eq!(cli.format, OutputFormat::Text);
        assert_eq!(cli.pp_macro_depth, 64);
        assert!(cli.positional_inputs.is_empty());
    }

    #[test]
    fn cli_parses_capability_introspection_flags() {
        let cli = Cli::parse_from(["opForge", "--print-capabilities", "--print-cpusupport"]);
        assert!(cli.print_capabilities);
        assert!(cli.print_cpusupport);
    }

    #[test]
    fn validate_cli_accepts_single_positional_input() {
        let cli = Cli::parse_from(["opForge", "prog.asm", "-l"]);
        let config = validate_cli(&cli).expect("validate cli");
        assert_eq!(config.input_paths, vec![PathBuf::from("prog.asm")]);
    }

    #[test]
    fn validate_cli_rejects_multiple_positional_inputs() {
        let cli = Cli::parse_from(["opForge", "a.asm", "b.asm", "-l"]);
        let err = validate_cli(&cli).expect_err("should reject multiple positionals");
        assert_eq!(
            err.to_string(),
            "Multiple positional inputs are not supported; use repeatable -i/--infile"
        );
    }

    #[test]
    fn validate_cli_rejects_mixed_positional_and_infile() {
        let cli = Cli::parse_from(["opForge", "legacy.asm", "-i", "modern.asm", "-l"]);
        let err = validate_cli(&cli).expect_err("should reject mixed input styles");
        assert_eq!(
            err.to_string(),
            "Do not mix positional input with -i/--infile; use one style"
        );
    }

    #[test]
    fn validate_cli_sets_diagnostics_and_warning_policy() {
        let cli = Cli::parse_from([
            "opForge",
            "-i",
            "prog.asm",
            "-l",
            "--format",
            "json",
            "--cpu",
            "m6502",
            "--labels",
            "symbols.lbl",
            "-E",
            "diag.log",
            "--error-append",
            "--dependencies",
            "deps.mk",
            "--dependencies-append",
            "--make-phony",
            "--Werror",
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        assert_eq!(config.output_format, OutputFormat::Json);
        assert_eq!(config.cpu_override.as_deref(), Some("m6502"));
        assert_eq!(config.labels_file, Some(PathBuf::from("symbols.lbl")));
        match config.diagnostics_sink {
            DiagnosticsSinkConfig::File { path, append } => {
                assert_eq!(path, PathBuf::from("diag.log"));
                assert!(append);
            }
            other => panic!("unexpected diagnostics sink: {other:?}"),
        }
        assert!(config.warning_policy.emit_warnings);
        assert!(config.warning_policy.treat_warnings_as_errors);
        let dep = config
            .dependency_output
            .as_ref()
            .expect("dependency policy present");
        assert_eq!(dep.path, PathBuf::from("deps.mk"));
        assert!(dep.append);
        assert!(dep.make_phony);
    }

    #[test]
    fn validate_cli_no_warn_disables_warnings() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l", "-w"]);
        let config = validate_cli(&cli).expect("validate cli");
        assert!(!config.warning_policy.emit_warnings);
    }

    #[test]
    fn validate_cli_allows_default_outputs_for_single_input() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm"]);
        let config = validate_cli(&cli).expect("validate cli");
        assert!(config.default_outputs);
    }

    #[test]
    fn validate_cli_rejects_zero_pp_macro_depth() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l", "--pp-macro-depth", "0"]);
        let err = validate_cli(&cli).unwrap_err();
        assert_eq!(err.to_string(), "--pp-macro-depth must be at least 1");
    }

    #[test]
    fn validate_cli_rejects_zero_tab_size() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l", "--tab-size", "0"]);
        let err = validate_cli(&cli).unwrap_err();
        assert_eq!(err.to_string(), "--tab-size must be at least 1");
    }

    #[test]
    fn validate_cli_applies_env_defaults_when_cli_not_set() {
        with_env_vars(
            &[
                ("OPFORGE_CPU", Some("m65816")),
                ("OPFORGE_INCLUDE_PATHS", Some("inc:shared")),
                ("OPFORGE_MODULE_PATHS", Some("mods")),
                ("OPFORGE_DEFINES", Some("BUILD=1,MODE=test")),
                ("OPFORGE_TAB_SIZE", Some("8")),
                ("OPFORGE_COND_DEBUG", Some("true")),
            ],
            || {
                let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l"]);
                let config = validate_cli(&cli).expect("validate cli");
                assert_eq!(config.cpu_override.as_deref(), Some("m65816"));
                assert_eq!(
                    config.include_paths,
                    vec![PathBuf::from("inc"), PathBuf::from("shared")]
                );
                assert_eq!(config.module_paths, vec![PathBuf::from("mods")]);
                assert_eq!(
                    config.defines,
                    vec!["BUILD=1".to_string(), "MODE=test".to_string()]
                );
                assert_eq!(config.tab_size, Some(8));
                assert!(config.debug_conditionals);
            },
        );
    }

    #[test]
    fn validate_cli_cli_values_override_env_values() {
        with_env_vars(
            &[
                ("OPFORGE_CPU", Some("m65816")),
                ("OPFORGE_QUIET", Some("true")),
                ("OPFORGE_TAB_SIZE", Some("8")),
            ],
            || {
                let cli = Cli::parse_from([
                    "opForge",
                    "-i",
                    "prog.asm",
                    "-l",
                    "--cpu",
                    "m6502",
                    "--tab-size",
                    "4",
                ]);
                let config = validate_cli(&cli).expect("validate cli");
                assert_eq!(config.cpu_override.as_deref(), Some("m6502"));
                assert_eq!(config.tab_size, Some(4));
                assert!(config.quiet);
            },
        );
    }

    #[test]
    fn validate_cli_rejects_invalid_env_boolean_value() {
        with_env_vars(&[("OPFORGE_WERROR", Some("maybe"))], || {
            let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l"]);
            let err = validate_cli(&cli).expect_err("invalid env bool should fail");
            assert!(err
                .to_string()
                .contains("Invalid boolean value for OPFORGE_WERROR"));
        });
    }

    #[test]
    fn validate_cli_rejects_label_format_without_labels_file() {
        with_env_vars(&[("OPFORGE_LABELS_FORMAT", Some("vice"))], || {
            let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l"]);
            let err = validate_cli(&cli).expect_err("labels format without labels should fail");
            assert_eq!(
                err.to_string(),
                "--vice-labels/--ctags-labels requires --labels"
            );
        });
    }

    #[test]
    fn validate_cli_rejects_dependency_append_without_dependency_file() {
        with_env_vars(&[("OPFORGE_DEPENDENCIES_APPEND", Some("1"))], || {
            let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-l"]);
            let err = validate_cli(&cli).expect_err("dependency append without file should fail");
            assert_eq!(
                err.to_string(),
                "--dependencies-append/--make-phony requires --dependencies"
            );
        });
    }

    #[test]
    fn parse_bin_allows_name_only() {
        let spec = parse_bin_output_arg("out.bin").expect("name only");
        assert_eq!(spec.name.as_deref(), Some("out.bin"));
        assert!(spec.range.is_none());
    }

    #[test]
    fn parse_bin_allows_empty() {
        let spec = parse_bin_output_arg("").expect("empty");
        assert!(spec.name.is_none());
        assert!(spec.range.is_none());
    }

    #[test]
    fn parse_bin_range_only() {
        let spec = parse_bin_output_arg("0100:01ff").expect("range only");
        assert!(spec.name.is_none());
        let range = spec.range.expect("range");
        assert_eq!(range.start, 0x0100);
        assert_eq!(range.end, 0x01ff);
    }

    #[test]
    fn parse_bin_named_range() {
        let spec = parse_bin_output_arg("out.bin:1000:10ff").expect("name + range");
        assert_eq!(spec.name.as_deref(), Some("out.bin"));
        let range = spec.range.expect("range");
        assert_eq!(range.start, 0x1000);
        assert_eq!(range.end, 0x10ff);
    }

    #[test]
    fn parse_bin_wide_range_only() {
        let spec = parse_bin_output_arg("010000:01ffff").expect("wide range only");
        assert!(spec.name.is_none());
        let range = spec.range.expect("range");
        assert_eq!(range.start, 0x010000);
        assert_eq!(range.end, 0x01ffff);
    }

    #[test]
    fn parse_bin_named_wide_range() {
        let spec = parse_bin_output_arg("out.bin:123456:1234ff").expect("name + wide range");
        assert_eq!(spec.name.as_deref(), Some("out.bin"));
        let range = spec.range.expect("range");
        assert_eq!(range.start, 0x123456);
        assert_eq!(range.end, 0x1234ff);
    }

    #[test]
    fn parse_bin_range_rejects_descending_bounds() {
        let err = parse_bin_output_arg("1000:0fff").expect_err("descending range should fail");
        assert_eq!(
            err,
            "Invalid -b/--bin range; must be ssss:eeee (4-8 hex digits, start <= end)"
        );
    }

    #[test]
    fn parse_bin_named_range_rejects_descending_bounds() {
        let err = parse_bin_output_arg("out.bin:2000:1fff")
            .expect_err("descending named range should fail");
        assert_eq!(
            err,
            "Invalid -b/--bin range; must be ssss:eeee (4-8 hex digits, start <= end)"
        );
    }

    #[test]
    fn validate_cli_accepts_wide_go() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-x", "-g", "123456"]);
        let config = validate_cli(&cli).expect("validate cli");
        assert_eq!(config.go_addr.as_deref(), Some("123456"));
    }

    #[test]
    fn validate_cli_rejects_short_go() {
        let cli = Cli::parse_from(["opForge", "-i", "prog.asm", "-x", "-g", "123"]);
        let err = validate_cli(&cli).expect_err("should reject short go");
        assert_eq!(
            err.to_string(),
            "Invalid -g/--go address; must be 4-8 hex digits"
        );
    }

    #[test]
    fn resolve_output_path_uses_base_on_empty_name() {
        assert_eq!(
            resolve_output_path("prog", Some(String::new()), "lst"),
            Some("prog.lst".to_string())
        );
    }

    #[test]
    fn resolve_output_path_preserves_extension() {
        assert_eq!(
            resolve_output_path("prog", Some("out.hex".to_string()), "hex"),
            Some("out.hex".to_string())
        );
    }

    #[test]
    fn resolve_output_path_appends_extension() {
        assert_eq!(
            resolve_output_path("prog", Some("out".to_string()), "hex"),
            Some("out.hex".to_string())
        );
    }

    #[test]
    fn resolve_bin_path_single_range_uses_base() {
        let range = range_0000_ffff();
        assert_eq!(
            resolve_bin_path("forth", None, Some(&range), 1, 0),
            "forth.bin"
        );
    }

    #[test]
    fn resolve_bin_path_multiple_ranges_adds_suffix() {
        let range = range_0000_ffff();
        assert_eq!(
            resolve_bin_path("forth", None, Some(&range), 2, 0),
            "forth-0000.bin"
        );
    }

    #[test]
    fn resolve_bin_path_multiple_no_ranges_adds_index() {
        assert_eq!(resolve_bin_path("forth", None, None, 2, 0), "forth-1.bin");
        assert_eq!(resolve_bin_path("forth", None, None, 2, 1), "forth-2.bin");
    }

    #[test]
    fn input_base_from_path_requires_asm_extension() {
        let err = input_base_from_path(&PathBuf::from("prog.txt"), &default_input_extensions())
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Input file must use one of these source extensions: .asm"
        );
    }

    #[test]
    fn input_base_from_path_requires_existing_asm_file() {
        let err = input_base_from_path(&PathBuf::from("missing.asm"), &default_input_extensions())
            .unwrap_err();
        assert_eq!(err.to_string(), "Input source file not found");
    }

    #[test]
    fn input_base_from_path_rejects_folder_named_asm() {
        let dir = create_temp_dir("input-folder-named-asm");
        let fake_file_dir = dir.join("my.asm");
        fs::create_dir_all(&fake_file_dir).expect("create folder named .asm");
        let err = input_base_from_path(&fake_file_dir, &default_input_extensions()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Input path has an accepted source extension but is a folder"
        );
    }

    #[test]
    fn input_base_from_dir_requires_main_module() {
        let dir = create_temp_dir("input-dir-missing");
        fs::write(dir.join("util.asm"), "; util").expect("write file");
        let err = input_base_from_path(&dir, &default_input_extensions()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Input folder must contain exactly one main.* root module"
        );
    }

    #[test]
    fn input_base_from_dir_rejects_multiple_main_modules() {
        let dir = create_temp_dir("input-dir-multiple");
        fs::write(dir.join("main.asm"), "; main").expect("write file");
        fs::write(dir.join("main.inc"), "; main inc").expect("write file");
        let err = input_base_from_path(&dir, &default_input_extensions()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Input folder contains multiple main.* root modules"
        );
    }

    #[test]
    fn input_base_from_dir_resolves_main_module() {
        let dir = create_temp_dir("input-dir-ok");
        let main_path = dir.join("main.asm");
        fs::write(&main_path, "; main").expect("write file");
        let (asm_name, base) =
            input_base_from_path(&dir, &default_input_extensions()).expect("resolve main");
        assert_eq!(PathBuf::from(asm_name), main_path);
        assert_eq!(base, dir.file_name().unwrap().to_string_lossy());
    }

    #[test]
    fn input_base_from_path_accepts_configured_asm_extensions_case_insensitive() {
        let dir = create_temp_dir("input-ext-custom");
        let src = dir.join("prog.S");
        fs::write(&src, "; src").expect("write custom extension file");
        let ext_policy = InputExtensionPolicy {
            asm_exts: vec!["asm".to_string(), "s".to_string()],
            inc_exts: vec!["inc".to_string(), "h".to_string()],
        };

        let (asm_name, base) = input_base_from_path(&src, &ext_policy).expect("resolve custom");
        assert_eq!(PathBuf::from(asm_name), src);
        assert_eq!(base, "prog");
    }

    #[test]
    fn input_base_from_dir_accepts_configured_inc_extensions_case_insensitive() {
        let dir = create_temp_dir("input-dir-custom-inc");
        let main_path = dir.join("main.H");
        fs::write(&main_path, "; main header style root").expect("write custom root");
        let ext_policy = InputExtensionPolicy {
            asm_exts: vec!["asm".to_string(), "s".to_string()],
            inc_exts: vec!["inc".to_string(), "h".to_string()],
        };

        let (asm_name, base) =
            input_base_from_path(&dir, &ext_policy).expect("resolve custom root module");
        assert_eq!(PathBuf::from(asm_name), main_path);
        assert_eq!(base, dir.file_name().unwrap().to_string_lossy());
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
}
