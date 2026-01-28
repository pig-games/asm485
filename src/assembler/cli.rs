// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Command-line interface parsing and argument validation.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};

use crate::core::assembler::error::{AsmError, AsmErrorKind, AsmRunError};

pub const VERSION: &str = "1.0";

const LONG_ABOUT: &str = "Intel 8085 Assembler with expressions, directives and basic macro support.

Outputs are opt-in: specify at least one of -l/--list, -x/--hex, or -b/--bin.
Use -o/--outfile to set the output base name when filenames are omitted.
For -b, ranges are required: ssss:eeee (4 hex digits each).
With multiple -b ranges and no filenames, outputs are named <base>-ssss.bin.
With multiple inputs, -o must be a directory and explicit output filenames are not allowed.";

#[derive(Parser, Debug)]
#[command(
    name = "asm485",
    version = VERSION,
    about = "Intel 8085 Assembler with expressions, directives and basic macro support",
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
        value_name = "FILE:ssss:eeee|ssss:eeee",
        num_args = 0..=1,
        default_missing_value = "",
        action = ArgAction::Append,
        long_help = "Emit a binary image file (repeatable). A range is required: ssss:eeee (4 hex digits each). Use ssss:eeee to use the output base, or FILE:ssss:eeee to override the filename. If FILE has no extension, .bin is added. If multiple -b ranges are provided without filenames, outputs are named <base>-ssss.bin."
    )]
    pub bin_outputs: Vec<String>,
    #[arg(
        short = 'f',
        long = "fill",
        value_name = "hh",
        long_help = "Fill byte for -b output (2 hex digits). Defaults to FF."
    )]
    pub fill_byte: Option<String>,
    #[arg(
        short = 'g',
        long = "go",
        value_name = "aaaa",
        long_help = "Set execution start address (4 hex digits). Adds a Start Segment Address record to hex output. Requires -x/--hex."
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
        value_name = "FILE",
        action = ArgAction::Append,
        long_help = "Input assembly file (repeatable). Must end with .asm."
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
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct BinOutputSpec {
    pub name: Option<String>,
    pub range: BinRange,
}

pub fn is_valid_hex_4(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_hex_2(s: &str) -> bool {
    s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_bin_range(s: &str) -> bool {
    if s.len() != 9 {
        return false;
    }
    if !s.as_bytes()[4].eq(&b':') {
        return false;
    }
    s.chars()
        .enumerate()
        .all(|(i, c)| (i == 4 && c == ':') || (i != 4 && c.is_ascii_hexdigit()))
}

pub fn parse_bin_output_arg(arg: &str) -> Result<BinOutputSpec, &'static str> {
    if arg.is_empty() {
        return Err("Missing -b/--bin argument; use ssss:eeee or name:ssss:eeee");
    }

    if let Some(range) = parse_bin_range_str(arg) {
        return Ok(BinOutputSpec { name: None, range });
    }

    if let Some((name_part, start, end)) = split_range_suffix(arg) {
        let range = parse_bin_range_parts(start, end)
            .ok_or("Invalid -b/--bin range; must be ssss:eeee (hex)")?;
        let name = if name_part.is_empty() {
            None
        } else {
            Some(name_part.to_string())
        };
        return Ok(BinOutputSpec { name, range });
    }

    Err("Binary output requires a range; use ssss:eeee or name:ssss:eeee")
}

fn split_range_suffix(s: &str) -> Option<(&str, &str, &str)> {
    let mut parts = s.rsplitn(3, ':');
    let end = parts.next()?;
    let start = parts.next()?;
    let name = parts.next()?;
    if is_valid_hex_4(start) && is_valid_hex_4(end) {
        Some((name, start, end))
    } else {
        None
    }
}

fn parse_bin_range_parts(start: &str, end: &str) -> Option<BinRange> {
    if !is_valid_hex_4(start) || !is_valid_hex_4(end) {
        return None;
    }
    let start_str = start.to_string();
    let end_str = end.to_string();
    let start = match u16::from_str_radix(&start_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let end = match u16::from_str_radix(&end_str, 16) {
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
    let start_str = s[..4].to_string();
    let end_str = s[5..].to_string();
    let start = match u16::from_str_radix(&start_str, 16) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let end = match u16::from_str_radix(&end_str, 16) {
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

pub fn resolve_bin_path(base: &str, name: Option<&str>, range: &BinRange, bin_count: usize) -> String {
    let name = match name {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            if bin_count == 1 {
                base.to_string()
            } else {
                format!("{base}-{}", range.start_str)
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

    if !list_requested && !hex_requested && !bin_requested {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Cli,
                "No outputs selected. Specify at least one of -l/--list, -x/--hex, or -b/--bin",
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
            if !hex_requested {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "-g/--go requires hex output (-x/--hex)",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            if !is_valid_hex_4(go) {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "Invalid -g/--go address; must be 4 hex digits",
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
            AsmRunError::new(AsmError::new(AsmErrorKind::Cli, msg, None), Vec::new(), Vec::new())
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

    let fill_byte = match cli.fill_byte.as_deref() {
        Some(fill) => {
            if !bin_requested {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Cli,
                        "-f/--fill requires binary output (-b/--bin)",
                        None,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
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
        out_dir,
        pp_macro_depth: cli.pp_macro_depth,
    })
}

/// Validated CLI configuration.
#[derive(Debug)]
pub struct CliConfig {
    pub go_addr: Option<String>,
    pub bin_specs: Vec<BinOutputSpec>,
    pub fill_byte: u8,
    pub out_dir: Option<PathBuf>,
    pub pp_macro_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn range_0000_ffff() -> BinRange {
        parse_bin_range_str("0000:ffff").expect("valid range")
    }

    #[test]
    fn cli_parses_outputs_and_inputs() {
        let cli = Cli::parse_from([
            "asm485",
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
        let cli = Cli::parse_from(["asm485", "-i", "prog.asm", "-l"]);
        assert_eq!(cli.pp_macro_depth, 64);
    }

    #[test]
    fn validate_cli_rejects_zero_pp_macro_depth() {
        let cli = Cli::parse_from([
            "asm485",
            "-i",
            "prog.asm",
            "-l",
            "--pp-macro-depth",
            "0",
        ]);
        let err = validate_cli(&cli).unwrap_err();
        assert_eq!(err.to_string(), "--pp-macro-depth must be at least 1");
    }

    #[test]
    fn parse_bin_requires_range() {
        assert!(parse_bin_output_arg("out.bin").is_err());
    }

    #[test]
    fn parse_bin_range_only() {
        let spec = parse_bin_output_arg("0100:01ff").expect("range only");
        assert!(spec.name.is_none());
        assert_eq!(spec.range.start, 0x0100);
        assert_eq!(spec.range.end, 0x01ff);
    }

    #[test]
    fn parse_bin_named_range() {
        let spec = parse_bin_output_arg("out.bin:1000:10ff").expect("name + range");
        assert_eq!(spec.name.as_deref(), Some("out.bin"));
        assert_eq!(spec.range.start, 0x1000);
        assert_eq!(spec.range.end, 0x10ff);
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
        assert_eq!(resolve_bin_path("forth", None, &range, 1), "forth.bin");
    }

    #[test]
    fn resolve_bin_path_multiple_ranges_adds_suffix() {
        let range = range_0000_ffff();
        assert_eq!(
            resolve_bin_path("forth", None, &range, 2),
            "forth-0000.bin"
        );
    }

    #[test]
    fn input_base_from_path_requires_asm_extension() {
        let err = input_base_from_path(&PathBuf::from("prog.txt")).unwrap_err();
        assert_eq!(err.to_string(), "Input file must end with .asm");
    }
}
