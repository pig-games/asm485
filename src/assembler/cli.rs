// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Command-line interface parsing and argument validation.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};

use crate::core::assembler::error::{AsmError, AsmErrorKind, AsmRunError};

pub const VERSION: &str = "0.9";

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
        long = "pp-macro-depth",
        value_name = "N",
        default_value_t = 64,
        long_help = "Maximum preprocessor macro expansion depth. Defaults to 64."
    )]
    pub pp_macro_depth: usize,
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
        let range = parse_bin_range_parts(start, end)
            .ok_or("Invalid -b/--bin range; must be ssss:eeee (4-8 hex digits)")?;
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

pub fn input_base_from_path(path: &Path) -> Result<(String, String), AsmRunError> {
    if path.is_dir() {
        return resolve_root_module_from_dir(path);
    }
    let asm_name = path.to_string_lossy().to_string();
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
    if !file_name.ends_with(".asm") {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Cli, "Input file must end with .asm", None),
            Vec::new(),
            Vec::new(),
        ));
    }
    let base = file_name.strip_suffix(".asm").unwrap_or(file_name);
    Ok((asm_name, base.to_string()))
}

fn resolve_root_module_from_dir(path: &Path) -> Result<(String, String), AsmRunError> {
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
        if !matches!(ext.to_ascii_lowercase().as_str(), "asm" | "inc") {
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

/// Validate CLI arguments and return parsed configuration.
pub fn validate_cli(cli: &Cli) -> Result<CliConfig, AsmRunError> {
    if cli.infiles.is_empty() {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "No input files specified. Use -i/--infile",
                None,
            ),
            Vec::new(),
            Vec::new(),
        ));
    }

    let list_requested = cli.list_name.is_some();
    let hex_requested = cli.hex_name.is_some();
    let bin_requested = !cli.bin_outputs.is_empty();

    let default_outputs = !list_requested && !hex_requested && !bin_requested;
    if default_outputs && cli.infiles.len() > 1 {
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

    if cli.infiles.len() > 1 {
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
    if cli.infiles.len() > 1 && bin_specs.iter().any(|spec| spec.name.is_some()) {
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

    let fill_byte_set = cli.fill_byte.is_some();
    let fill_byte = match cli.fill_byte.as_deref() {
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

    let out_dir = if cli.infiles.len() > 1 {
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

    if cli.pp_macro_depth == 0 {
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

    Ok(CliConfig {
        go_addr,
        bin_specs,
        fill_byte,
        fill_byte_set,
        out_dir,
        pp_macro_depth: cli.pp_macro_depth,
        default_outputs,
    })
}

/// Validated CLI configuration.
#[derive(Debug)]
pub struct CliConfig {
    pub go_addr: Option<String>,
    pub bin_specs: Vec<BinOutputSpec>,
    pub fill_byte: u8,
    pub fill_byte_set: bool,
    pub out_dir: Option<PathBuf>,
    pub pp_macro_depth: usize,
    pub default_outputs: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn range_0000_ffff() -> BinRange {
        parse_bin_range_str("0000:ffff").expect("valid range")
    }

    #[test]
    fn cli_parses_outputs_and_inputs() {
        let cli = Cli::parse_from([
            "opForge",
            "-i",
            "prog.asm",
            "-l",
            "-x",
            "-b",
            "0000:ffff",
            "-o",
            "out",
            "-f",
            "aa",
            "--pp-macro-depth",
            "80",
        ]);
        assert_eq!(cli.infiles, vec![PathBuf::from("prog.asm")]);
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
        assert_eq!(cli.pp_macro_depth, 64);
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
        let err = input_base_from_path(&PathBuf::from("prog.txt")).unwrap_err();
        assert_eq!(err.to_string(), "Input file must end with .asm");
    }

    #[test]
    fn input_base_from_dir_requires_main_module() {
        let dir = create_temp_dir("input-dir-missing");
        fs::write(dir.join("util.asm"), "; util").expect("write file");
        let err = input_base_from_path(&dir).unwrap_err();
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
        let err = input_base_from_path(&dir).unwrap_err();
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
        let (asm_name, base) = input_base_from_path(&dir).expect("resolve main");
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
