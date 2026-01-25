// Assembler core pipeline and listing/output generation.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{ArgAction, Parser};

use crate::imagestore::ImageStore;
use crate::instructions::table::INSTRUCTION_TABLE;
use crate::instructions::ArgType;
use crate::preprocess::Preprocessor;
use crate::scanner::{Scanner, TokenType, TokenValue};
use crate::symbol_table::{SymbolTable, NO_ENTRY};

const VERSION: &str = "1.0";
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
struct Cli {
    #[arg(
        short = 'l',
        long = "list",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        long_help = "Emit a listing file. FILE is optional; when omitted, the output base is used and a .lst extension is added."
    )]
    list_name: Option<String>,
    #[arg(
        short = 'x',
        long = "hex",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        long_help = "Emit an Intel Hex file. FILE is optional; when omitted, the output base is used and a .hex extension is added."
    )]
    hex_name: Option<String>,
    #[arg(
        short = 'o',
        long = "outfile",
        value_name = "BASE",
        long_help = "Output filename base when -l/-x omit filenames, and for -b when a filename is omitted. Defaults to the input base. With multiple inputs, BASE must be a directory."
    )]
    outfile: Option<String>,
    #[arg(
        short = 'b',
        long = "bin",
        value_name = "FILE:ssss:eeee|ssss:eeee",
        num_args = 0..=1,
        default_missing_value = "",
        action = ArgAction::Append,
        long_help = "Emit a binary image file (repeatable). A range is required: ssss:eeee (4 hex digits each). Use ssss:eeee to use the output base, or FILE:ssss:eeee to override the filename. If FILE has no extension, .bin is added. If multiple -b ranges are provided without filenames, outputs are named <base>-ssss.bin."
    )]
    bin_outputs: Vec<String>,
    #[arg(
        short = 'f',
        long = "fill",
        value_name = "hh",
        long_help = "Fill byte for -b output (2 hex digits). Defaults to FF."
    )]
    fill_byte: Option<String>,
    #[arg(
        short = 'g',
        long = "go",
        value_name = "aaaa",
        long_help = "Set execution start address (4 hex digits). Adds a Start Segment Address record to hex output. Requires -x/--hex."
    )]
    go_addr: Option<String>,
    #[arg(
        short = 'c',
        long = "cond-debug",
        action = ArgAction::SetTrue,
        long_help = "Append conditional assembly state to listing lines."
    )]
    debug_conditionals: bool,
    #[arg(
        short = 'D',
        long = "define",
        value_name = "NAME[=VAL]",
        action = ArgAction::Append,
        long_help = "Predefine a macro (repeatable). If VAL is omitted, defaults to 1."
    )]
    defines: Vec<String>,
    #[arg(
        short = 'i',
        long = "infile",
        value_name = "FILE",
        action = ArgAction::Append,
        long_help = "Input assembly file (repeatable). Must end with .asm."
    )]
    infiles: Vec<PathBuf>,
}

pub fn run() -> Result<Vec<AsmRunReport>, AsmRunError> {
    let cli = Cli::parse();
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
            if !is_valid_hex_4(&go) {
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
            if !is_valid_hex_2(&fill) {
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
            u8::from_str_radix(&fill, 16).unwrap_or(0xff)
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

    let mut reports = Vec::new();
    for asm_path in &cli.infiles {
        let (asm_name, input_base) = input_base_from_path(asm_path)?;
        let out_base = if let Some(dir) = &out_dir {
            dir.join(&input_base).to_string_lossy().to_string()
        } else {
            cli.outfile.as_deref().unwrap_or(&input_base).to_string()
        };
        let report = run_one(
            &cli,
            &asm_name,
            &out_base,
            &bin_specs,
            go_addr.as_deref(),
            fill_byte,
        )?;
        reports.push(report);
    }

    Ok(reports)
}

fn run_one(
    cli: &Cli,
    asm_name: &str,
    out_base: &str,
    bin_specs: &[BinOutputSpec],
    go_addr: Option<&str>,
    fill_byte: u8,
) -> Result<AsmRunReport, AsmRunError> {
    let list_path = resolve_output_path(out_base, cli.list_name.clone(), "lst");
    let hex_path = resolve_output_path(out_base, cli.hex_name.clone(), "hex");

    let mut pp = Preprocessor::new();
    for def in &cli.defines {
        if let Some((name, value)) = def.split_once('=') {
            pp.define(name, value);
        } else {
            pp.define(def, "1");
        }
    }
    if let Err(err) = pp.process_file(asm_name) {
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
    let src_lines: Vec<String> = pp.lines().to_vec();

    let mut assembler = Assembler::new();
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&src_lines);
    if pass1.errors > 0 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Assembler,
                "Errors detected in source. No hex file created.",
                None,
            ),
            assembler.take_diagnostics(),
            src_lines.clone(),
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
    if let Err(err) = listing.header() {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            assembler.take_diagnostics(),
            src_lines.clone(),
        ));
    }
    let pass2 = match assembler.pass2(&src_lines, &mut listing) {
        Ok(counts) => counts,
        Err(err) => {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                src_lines.clone(),
            ))
        }
    };
    if let Err(err) = listing.footer(&pass2, assembler.symbols(), assembler.image().num_entries()) {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            assembler.take_diagnostics(),
            src_lines.clone(),
        ));
    }

    if let Some(hex_path) = &hex_path {
        let mut hex_file = File::create(hex_path).map_err(|_| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, "Error opening file for write", Some(hex_path)),
                assembler.take_diagnostics(),
                src_lines.clone(),
            )
        })?;
        if let Err(err) = assembler.image().write_hex_file(&mut hex_file, go_addr.as_deref()) {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                src_lines.clone(),
            ));
        }
    }

    let mut bin_outputs = Vec::new();
    let bin_count = bin_specs.len();
    for spec in bin_specs {
        let bin_name = resolve_bin_path(out_base, spec.name.as_deref(), &spec.range, bin_count);
        bin_outputs.push((bin_name, spec.range.clone()));
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
                    src_lines.clone(),
                ))
            }
        };
        if let Err(err) =
            assembler
                .image()
                .write_bin_file(&mut bin_file, range.start, range.end, fill_byte)
        {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                src_lines.clone(),
            ));
        }
    }

    Ok(AsmRunReport::new(
        assembler.take_diagnostics(),
        src_lines,
    ))
}

fn input_base_from_path(path: &PathBuf) -> Result<(String, String), AsmRunError> {
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
fn is_valid_hex_4(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_hex_2(s: &str) -> bool {
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

#[derive(Debug, Clone)]
struct BinRange {
    start_str: String,
    start: u16,
    end: u16,
}

#[derive(Debug, Clone)]
struct BinOutputSpec {
    name: Option<String>,
    range: BinRange,
}

fn parse_bin_output_arg(arg: &str) -> Result<BinOutputSpec, &'static str> {
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
    let start = u16::from_str_radix(&start_str, 16).unwrap_or(0);
    let end = u16::from_str_radix(&end_str, 16).unwrap_or(0);
    Some(BinRange {
        start_str,
        start,
        end,
    })
}

fn parse_bin_range_str(s: &str) -> Option<BinRange> {
    if !is_valid_bin_range(s) {
        return None;
    }
    let start_str = s[..4].to_string();
    let end_str = s[5..].to_string();
    let start = u16::from_str_radix(&start_str, 16).unwrap_or(0);
    let end = u16::from_str_radix(&end_str, 16).unwrap_or(0);
    Some(BinRange {
        start_str,
        start,
        end,
    })
}

fn resolve_output_path(base: &str, name: Option<String>, extension: &str) -> Option<String> {
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

fn resolve_bin_path(base: &str, name: Option<&str>, range: &BinRange, bin_count: usize) -> String {
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

#[derive(Debug, Default, Clone, Copy)]
struct PassCounts {
    lines: u32,
    errors: u32,
    warnings: u32,
}

impl PassCounts {
    fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsmErrorKind {
    Assembler,
    Cli,
    Conditional,
    Directive,
    Expression,
    Instruction,
    Io,
    Preprocess,
    Scanner,
    Symbol,
}

#[derive(Debug, Clone)]
struct AsmError {
    #[allow(dead_code)]
    kind: AsmErrorKind,
    message: String,
}

impl AsmError {
    fn new(kind: AsmErrorKind, msg: &str, param: Option<&str>) -> Self {
        Self {
            kind,
            message: format_error(msg, param),
        }
    }

    fn message(&self) -> &str {
        &self.message
    }

    fn kind(&self) -> AsmErrorKind {
        self.kind
    }
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AsmError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    line: u32,
    column: Option<usize>,
    severity: Severity,
    error: AsmError,
    file: Option<String>,
    source: Option<String>,
}

impl Diagnostic {
    fn new(line: u32, severity: Severity, error: AsmError) -> Self {
        Self {
            line,
            column: None,
            severity,
            error,
            file: None,
            source: None,
        }
    }

    fn with_column(mut self, column: Option<usize>) -> Self {
        self.column = column;
        self
    }

    fn with_file(mut self, file: Option<String>) -> Self {
        self.file = file;
        self
    }

    fn with_source(mut self, source: Option<String>) -> Self {
        self.source = source;
        self
    }

    pub fn format(&self) -> String {
        let sev = match self.severity {
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
        };
        format!("{}: {} - {}", self.line, sev, self.error.message())
    }

    pub fn format_with_context(&self, lines: Option<&[String]>, use_color: bool) -> String {
        let sev = match self.severity {
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
        };
        let header = match &self.file {
            Some(file) => format!("{file}:{}: {sev}", self.line),
            None => format!("{}: {sev}", self.line),
        };

        let mut out = String::new();
        out.push_str(&header);
        out.push('\n');

        let context = build_context_lines(self.line, self.column, lines, self.source.as_deref(), use_color);
        for line in context {
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str(&format!("{sev}: {}", self.error.message()));
        out
    }
}

pub struct AsmRunReport {
    diagnostics: Vec<Diagnostic>,
    source_lines: Vec<String>,
}

impl AsmRunReport {
    fn new(diagnostics: Vec<Diagnostic>, source_lines: Vec<String>) -> Self {
        Self {
            diagnostics,
            source_lines,
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn source_lines(&self) -> &[String] {
        &self.source_lines
    }

    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }
}

#[derive(Debug)]
pub struct AsmRunError {
    error: AsmError,
    diagnostics: Vec<Diagnostic>,
    source_lines: Vec<String>,
}

impl AsmRunError {
    fn new(error: AsmError, diagnostics: Vec<Diagnostic>, source_lines: Vec<String>) -> Self {
        Self {
            error,
            diagnostics,
            source_lines,
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn source_lines(&self) -> &[String] {
        &self.source_lines
    }
}

impl fmt::Display for AsmRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for AsmRunError {}

struct Assembler {
    symbols: SymbolTable,
    image: ImageStore,
    diagnostics: Vec<Diagnostic>,
}

impl Assembler {
    fn new() -> Self {
        Self {
            symbols: SymbolTable::new(),
            image: ImageStore::new(65536),
            diagnostics: Vec::new(),
        }
    }

    fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    fn image(&self) -> &ImageStore {
        &self.image
    }

    fn clear_diagnostics(&mut self) {
        self.diagnostics.clear();
    }

    fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    fn pass1(&mut self, lines: &[String]) -> PassCounts {
        let mut asm_line = AsmLine::new(&mut self.symbols);
        asm_line.clear_conditionals();
        let mut addr: u16 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;

        for src in lines {
            let status = asm_line.process(src, line_num, addr, 1);
            if status == LineStatus::Pass1Error {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(
                        Diagnostic::new(line_num, Severity::Error, err.clone())
                            .with_column(asm_line.error_column()),
                    );
                }
                counts.errors += 1;
            } else if status == LineStatus::DirDs {
                addr = asm_line.start_addr().wrapping_add(asm_line.aux_value());
            } else {
                addr = asm_line
                    .start_addr()
                    .wrapping_add(asm_line.num_bytes() as u16);
            }
            line_num += 1;
        }

        if !asm_line.cond_is_empty() {
            let err = AsmError::new(
                AsmErrorKind::Conditional,
                "Found IF without ENDIF in pass 1",
                None,
            );
            diagnostics.push(Diagnostic::new(line_num, Severity::Warning, err));
            asm_line.clear_conditionals();
            counts.warnings += 1;
        }

        counts.lines = line_num - 1;
        counts
    }

    fn pass2<W: Write>(
        &mut self,
        lines: &[String],
        listing: &mut ListingWriter<W>,
    ) -> std::io::Result<PassCounts> {
        let mut asm_line = AsmLine::new(&mut self.symbols);
        asm_line.clear_conditionals();
        self.image = ImageStore::new(65536);

        let mut addr: u16 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;
        let image = &mut self.image;

        for src in lines {
            let status = asm_line.process(src, line_num, addr, 2);
            addr = asm_line.start_addr();
            let bytes = asm_line.bytes();
            if !bytes.is_empty() {
                image.store_slice(addr, bytes);
            }

            listing.write_line(ListingLine {
                addr,
                bytes,
                status,
                aux: asm_line.aux_value(),
                line_num,
                source: src,
                cond: asm_line.cond_last(),
            })?;

            match status {
                LineStatus::Error => {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column()),
                        );
                        listing.write_diagnostic(
                            "ERROR",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                        )?;
                    }
                    counts.errors += 1;
                }
                LineStatus::Warning => {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Warning, err.clone())
                                .with_column(asm_line.error_column()),
                        );
                        listing.write_diagnostic(
                            "WARNING",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                        )?;
                    }
                    counts.warnings += 1;
                }
                _ => {}
            }

            if status == LineStatus::DirDs {
                addr = addr.wrapping_add(asm_line.aux_value());
            } else {
                addr = addr.wrapping_add(asm_line.num_bytes() as u16);
            }
            line_num += 1;
        }

        if !asm_line.cond_is_empty() {
            let err = AsmError::new(AsmErrorKind::Conditional, "Found IF without ENDIF", None);
            diagnostics.push(Diagnostic::new(line_num, Severity::Error, err.clone()));
            listing.write_diagnostic("ERROR", err.message(), line_num, None, lines)?;
            asm_line.clear_conditionals();
            counts.errors += 1;
        }

        counts.lines = line_num - 1;
        Ok(counts)
    }
}

struct ListingLine<'a> {
    addr: u16,
    bytes: &'a [u8],
    status: LineStatus,
    aux: u16,
    line_num: u32,
    source: &'a str,
    cond: Option<&'a ConditionalContext>,
}

struct ListingWriter<W: Write> {
    out: W,
    show_cond: bool,
}

impl<W: Write> ListingWriter<W> {
    fn new(out: W, show_cond: bool) -> Self {
        Self { out, show_cond }
    }

    fn header(&mut self) -> std::io::Result<()> {
        writeln!(self.out, "asm485 8085 Assembler v{VERSION}")?;
        writeln!(self.out, "ADDR    BYTES                    LINE  SOURCE")?;
        writeln!(self.out, "------  -----------------------  ----  ------")?;
        Ok(())
    }

    fn write_line(&mut self, line: ListingLine<'_>) -> std::io::Result<()> {
        let (loc, bytes_col) = match line.status {
            LineStatus::DirEqu => (String::new(), format!("EQU {:04X}", line.aux)),
            LineStatus::DirDs => (format!("{:04X}", line.addr), format!("+{:04X}", line.aux)),
            _ => {
                if line.bytes.is_empty() {
                    ("".to_string(), String::new())
                } else {
                    (format!("{:04X}", line.addr), format_bytes(line.bytes))
                }
            }
        };

        let loc = if loc.is_empty() { "----".to_string() } else { loc };
        let cond_str = if self.show_cond {
            line.cond.map(format_cond).unwrap_or_default()
        } else {
            String::new()
        };

        writeln!(
            self.out,
            "{:<6}  {:<23}  {:>4}  {}{}",
            loc, bytes_col, line.line_num, line.source, cond_str
        )
    }

    fn write_diagnostic(
        &mut self,
        kind: &str,
        msg: &str,
        line_num: u32,
        column: Option<usize>,
        source_lines: &[String],
    ) -> std::io::Result<()> {
        let context = build_context_lines(line_num, column, Some(source_lines), None, true);
        for line in context {
            writeln!(self.out, "{line}")?;
        }
        writeln!(self.out, "{kind}: {msg}")
    }

    fn footer(
        &mut self,
        counts: &PassCounts,
        symbols: &SymbolTable,
        total_mem: usize,
    ) -> std::io::Result<()> {
        writeln!(
            self.out,
            "\nLines: {}  Errors: {}  Warnings: {}",
            counts.lines, counts.errors, counts.warnings
        )?;
        writeln!(self.out, "\nSYMBOL TABLE\n")?;
        symbols.dump(&mut self.out)?;
        writeln!(self.out, "\nTotal memory is {} bytes", total_mem)?;
        Ok(())
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn build_context_lines(
    line_num: u32,
    column: Option<usize>,
    lines: Option<&[String]>,
    source_override: Option<&str>,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let line_idx = line_num.saturating_sub(1) as usize;

    if let Some(source) = source_override {
        let highlighted = highlight_line(source, column, use_color);
        out.push(format!("{:>5} | {}", line_num, highlighted));
        return out;
    }

    let lines = match lines {
        Some(lines) if !lines.is_empty() => lines,
        _ => {
            out.push(format!("{:>5} | <source unavailable>", line_num));
            return out;
        }
    };

    if line_idx >= lines.len() {
        out.push(format!("{:>5} | <source unavailable>", line_num));
        return out;
    }

    let line = &lines[line_idx];
    let display = highlight_line(line, column, use_color);
    out.push(format!("{:>5} | {}", line_num, display));

    out
}

fn highlight_line(line: &str, column: Option<usize>, use_color: bool) -> String {
    let col = match column {
        Some(c) if c > 0 => c,
        _ => return line.to_string(),
    };
    let idx = col - 1;
    if idx >= line.len() {
        if use_color {
            return format!("{line}\x1b[31m^\x1b[0m");
        }
        return format!("{line}^");
    }
    let (head, tail) = line.split_at(idx);
    let ch = tail.chars().next().unwrap_or(' ');
    let rest = &tail[ch.len_utf8()..];
    if use_color {
        format!("{head}\x1b[31m{ch}\x1b[0m{rest}")
    } else {
        format!("{head}{ch}{rest}")
    }
}

fn format_cond(ctx: &ConditionalContext) -> String {
    let matched = if ctx.matched { '+' } else { ' ' };
    let skipping = if ctx.skipping { '-' } else { ' ' };
    format!("  [{}{}{}{}]", matched, ctx.nest_level, ctx.skip_level, skipping)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LineStatus {
    Ok = 0,
    DirEqu = 1,
    DirDs = 2,
    NothingDone = 3,
    Skip = 4,
    BadStatuses = 5,
    Warning = 6,
    Error = 7,
    Pass1Error = 8,
}

#[derive(Debug, Clone)]
struct ConditionalContext {
    nest_level: u8,
    skip_level: u8,
    sub_type: i32,
    matched: bool,
    skipping: bool,
}

impl ConditionalContext {
    fn new(prev: Option<&ConditionalContext>) -> Self {
        let nest_level = match prev {
            Some(p) => p.nest_level.saturating_add(1),
            None => 1,
        };
        Self {
            nest_level,
            skip_level: 0,
            sub_type: TokenValue::If as i32,
            matched: false,
            skipping: false,
        }
    }
}

struct ConditionalStack {
    stack: Vec<ConditionalContext>,
}

impl ConditionalStack {
    fn new() -> Self {
        Self { stack: Vec::new() }
    }

    fn clear(&mut self) {
        self.stack.clear();
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    fn last(&self) -> Option<&ConditionalContext> {
        self.stack.last()
    }

    fn last_mut(&mut self) -> Option<&mut ConditionalContext> {
        self.stack.last_mut()
    }

    fn push(&mut self, ctx: ConditionalContext) {
        self.stack.push(ctx);
    }

    fn pop(&mut self) -> Option<ConditionalContext> {
        self.stack.pop()
    }

    fn skipping(&self) -> bool {
        self.stack.last().map(|c| c.skipping).unwrap_or(false)
    }
}

struct AsmLine<'a> {
    symbols: &'a mut SymbolTable,
    cond_stack: ConditionalStack,
    last_error: Option<AsmError>,
    last_error_column: Option<usize>,
    bytes: Vec<u8>,
    start_addr: u16,
    aux_value: u16,
    scanner: Scanner,
    pass: u8,
    label_kind: i32,
    label: Option<String>,
    mnemonic: Option<String>,
}

impl<'a> AsmLine<'a> {
    fn new(symbols: &'a mut SymbolTable) -> Self {
        Self {
            symbols,
            cond_stack: ConditionalStack::new(),
            last_error: None,
            last_error_column: None,
            bytes: Vec::with_capacity(256),
            start_addr: 0,
            aux_value: 0,
            scanner: Scanner::new(),
            pass: 1,
            label_kind: TokenValue::None as i32,
            label: None,
            mnemonic: None,
        }
    }

    fn error(&self) -> Option<&AsmError> {
        self.last_error.as_ref()
    }

    fn error_column(&self) -> Option<usize> {
        self.last_error_column
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

    fn start_addr(&self) -> u16 {
        self.start_addr
    }

    fn aux_value(&self) -> u16 {
        self.aux_value
    }

    fn clear_conditionals(&mut self) {
        self.cond_stack.clear();
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

    #[cfg(test)]
    fn symbols(&self) -> &SymbolTable {
        &*self.symbols
    }

    fn is_bad_status(status: LineStatus) -> bool {
        status > LineStatus::BadStatuses
    }

    fn process(
        &mut self,
        line: &str,
        _line_num: u32,
        addr: u16,
        pass: u8,
    ) -> LineStatus {
        self.last_error = None;
        self.last_error_column = None;
        self.start_addr = addr;
        self.pass = pass;
        self.bytes.clear();
        self.aux_value = 0;

        self.label = None;
        self.mnemonic = None;
        self.label_kind = TokenValue::None as i32;

        let mut t = self.scanner.init(line);
        if t == TokenType::Label {
            self.label = Some(self.scanner.get_string().to_string());
            self.label_kind = self.scanner.get_value();
            t = self.scanner.next_token();
        }
        if t == TokenType::Identifier {
            self.mnemonic = Some(self.scanner.get_string().to_string());
            self.scanner.next_token();
        } else if t == TokenType::Error {
            let msg = self.scanner.get_error_msg().to_string();
            return self.failure(LineStatus::Error, AsmErrorKind::Scanner, &msg, None);
        }

        let mut status = self.process_conditional();
        if status == LineStatus::Skip {
            return LineStatus::NothingDone;
        }
        let stop_after_label = status == LineStatus::Ok;

        if let Some(label) = self.label.clone() {
            if self.label_kind == TokenValue::Label as i32 {
                let res = if self.pass == 1 {
                    self.symbols.add(&label, self.start_addr as u32, false)
                } else {
                    self.symbols.update(&label, self.start_addr as u32)
                };
                if res == crate::symbol_table::SymbolTableResult::Duplicate {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "Symbol defined more than once",
                        Some(&label),
                        Some(1),
                    );
                }
            }
        }

        if stop_after_label {
            return if self.scanner.is_end() {
                LineStatus::Ok
            } else {
                let token = self.scanner.get_string().to_string();
                self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Assembler,
                    "Expecting end of line, found",
                    Some(&token),
                )
            };
        }

        if self.mnemonic.is_some() {
            status = self.process_directive();
        }

        if status == LineStatus::NothingDone {
            if self.label_kind == TokenValue::Name as i32 {
                let label = self.label.clone().unwrap_or_default();
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Assembler,
                    "Expecting label, comment, or space n column 1, found",
                    Some(&label),
                    Some(1),
                );
            }
            if self.mnemonic.is_some() {
                status = self.process_instruction();
            }
        }

        if Self::is_bad_status(status) || self.scanner.is_end() {
            status
        } else {
            let token = self.scanner.get_string().to_string();
            self.failure(
                LineStatus::Error,
                AsmErrorKind::Assembler,
                "Expecting end of line, found",
                Some(&token),
            )
        }
    }

    fn failure(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
    ) -> LineStatus {
        let column = self.scanner.token_start().saturating_add(1);
        self.failure_at(status, kind, msg, param, Some(column))
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

    fn evaluate_expression(&mut self) -> Result<u32, AsmError> {
        let mut eval =
            ExprEvaluator::new(&mut self.scanner, &*self.symbols, self.pass, self.start_addr);
        eval.eval_expression()
    }

    fn process_conditional(&mut self) -> LineStatus {
        if self.mnemonic.is_some() {
            return LineStatus::NothingDone;
        }
        let skipping = self.cond_stack.skipping();

        if self.scanner.get_type() == TokenType::Conditional && self.mnemonic.is_none() {
            let sub_type = self.scanner.get_value();
            self.scanner.next();
            match sub_type {
                t if t == TokenValue::If as i32 => {
                    let val = self.evaluate_expression().unwrap_or(0);
                    if skipping {
                        if let Some(ctx) = self.cond_stack.last_mut() {
                            ctx.skip_level = ctx.skip_level.saturating_add(1);
                        }
                        return LineStatus::Skip;
                    }
                    let prev = self.cond_stack.last();
                    let mut ctx = ConditionalContext::new(prev);
                    if (val & 1) != 0 {
                        ctx.matched = true;
                    } else {
                        ctx.skipping = true;
                    }
                    self.cond_stack.push(ctx);
                }
                t if t == TokenValue::Else as i32 || t == TokenValue::ElseIf as i32 => {
                    if self.cond_stack.is_empty() {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            "ELSE or ELSEIF found without matching IF",
                            None,
                        );
                    }
                    let skip_level = self
                        .cond_stack
                        .last()
                        .map(|ctx| ctx.skip_level)
                        .unwrap_or(0);
                    if skip_level > 0 {
                        self.scanner.skip_to_end();
                        return LineStatus::Skip;
                    }
                    let val = if sub_type == TokenValue::Else as i32 {
                        1
                    } else {
                        self.evaluate_expression().unwrap_or(0) & 1
                    };
                    let ctx = self.cond_stack.last_mut().unwrap();
                    if ctx.sub_type == TokenValue::Else as i32 {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            "ELSE or ELSEIF cannot follow ELSE",
                            None,
                        );
                    }
                    if !ctx.skipping {
                        ctx.skipping = true;
                        ctx.sub_type = sub_type;
                    } else if !ctx.matched && val != 0 {
                        ctx.matched = true;
                        ctx.skipping = false;
                        ctx.sub_type = sub_type;
                    }
                }
                t if t == TokenValue::EndIf as i32 => {
                    if self.cond_stack.is_empty() {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            "ENDIF found without matching IF",
                            None,
                        );
                    }
                    let ctx = self.cond_stack.last_mut().unwrap();
                    if ctx.skip_level > 0 {
                        ctx.skip_level -= 1;
                        return LineStatus::Skip;
                    }
                    self.cond_stack.pop();
                }
                _ => {}
            }
            return LineStatus::Ok;
        }

        if skipping {
            self.scanner.skip_to_end();
            return LineStatus::Skip;
        }

        LineStatus::NothingDone
    }

    fn process_directive(&mut self) -> LineStatus {
        let mnemonic = match self.mnemonic.clone() {
            Some(m) => m,
            None => return LineStatus::NothingDone,
        };
        let upper = mnemonic.to_ascii_uppercase();

        match upper.as_str() {
            "ORG" => {
                let val = match self.evaluate_expression() {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure(LineStatus::Error, err.kind(), err.message(), None)
                    }
                };
                self.start_addr = val as u16;
                self.aux_value = val as u16;
                LineStatus::DirEqu
            }
            "EQU" | "SET" => {
                if self.label.is_none() {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Must specify name before EQU or SET",
                        None,
                        Some(1),
                    );
                }
                if self.label_kind != TokenValue::Name as i32 {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "EQU or SET name should not end in ':'",
                        None,
                        Some(1),
                    );
                }
                let is_rw = upper == "SET";
                let val = match self.evaluate_expression() {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure(LineStatus::Error, err.kind(), err.message(), None)
                    }
                };
                let label = self.label.clone().unwrap_or_default();
                let res = if self.pass == 1 {
                    self.symbols.add(&label, val, is_rw)
                } else {
                    self.symbols.update(&label, val)
                };
                if res == crate::symbol_table::SymbolTableResult::Duplicate {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "symbol has already been defined",
                        Some(&label),
                        Some(1),
                    );
                } else if res == crate::symbol_table::SymbolTableResult::TableFull {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "could not add symbol, table full",
                        Some(&label),
                        Some(1),
                    );
                }
                self.aux_value = val as u16;
                LineStatus::DirEqu
            }
            "DB" => self.store_arg_list(1),
            "DW" => self.store_arg_list(2),
            "DS" => {
                let val = match self.evaluate_expression() {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure(LineStatus::Error, err.kind(), err.message(), None)
                    }
                };
                self.aux_value = val as u16;
                LineStatus::DirDs
            }
            "END" => LineStatus::Ok,
            "CPU" => {
                let cpu = self.scanner.get_string().to_string();
                if cpu != "8085" && cpu != "8080" {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unsupported CPU type, must be 8085 or 8080",
                        Some(&cpu),
                    );
                }
                self.scanner.skip_to_end();
                LineStatus::Ok
            }
            _ => LineStatus::NothingDone,
        }
    }

    fn process_instruction(&mut self) -> LineStatus {
        let mnemonic = match self.mnemonic.clone() {
            Some(m) => m,
            None => return LineStatus::NothingDone,
        };
        let upper = mnemonic.to_ascii_uppercase();

        if upper == "RST" {
            let arg = self.scanner.get_string().to_string();
            if self.scanner.get_type() != TokenType::Constant
                || arg.len() != 1
                || !matches!(arg.as_bytes()[0], b'0'..=b'7')
            {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    "RST instruction argument must be 0-7",
                    Some(&arg),
                );
            }
            let val = arg.as_bytes()[0] - b'0';
            self.bytes.push(0xc7 | (val << 3));
            if self.scanner.next_token() != TokenType::Eof {
                let token = self.scanner.get_string().to_string();
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    "Found extra arguments after RST instruction",
                    Some(&token),
                );
            }
            return LineStatus::Ok;
        }

        let mut num_regs = 0;
        let mut reg1 = String::new();
        let mut reg2 = String::new();

        if self.scanner.get_type() == TokenType::Register {
            reg1 = self.scanner.get_string().to_string();
            num_regs += 1;
            if self.scanner.peek_char() == b',' {
                self.scanner.next();
                self.scanner.next();
                if self.scanner.get_type() == TokenType::Register {
                    reg2 = self.scanner.get_string().to_string();
                    num_regs += 1;
                }
            }
        }

        let mut mnemonic_found = false;
        for inst in INSTRUCTION_TABLE {
            let cmp = cmp_ignore_ascii_case(inst.mnemonic, &mnemonic);
            if cmp == std::cmp::Ordering::Equal {
                mnemonic_found = true;
                if inst.num_regs as i32 == num_regs - 1 && inst.arg_type != ArgType::None {
                    self.scanner.change_register_to_id();
                    num_regs -= 1;
                } else if inst.num_regs as i32 != num_regs {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        "Wrong number of register arguments for instruction",
                        Some(&mnemonic),
                    );
                }
                if inst.num_regs >= 1 && !inst.reg1.eq_ignore_ascii_case(&reg1) {
                    continue;
                }
                if inst.num_regs == 2 && !inst.reg2.eq_ignore_ascii_case(&reg2) {
                    continue;
                }
                self.bytes.push(inst.opcode);
                if inst.arg_type != ArgType::None {
                    let val = match self.evaluate_expression() {
                        Ok(value) => value,
                        Err(err) => {
                            return self.failure(LineStatus::Error, err.kind(), err.message(), None)
                        }
                    };
                    self.bytes.push((val & 0xff) as u8);
                    if inst.arg_type == ArgType::Word {
                        self.bytes.push((val >> 8) as u8);
                    }
                } else if self.scanner.get_type() == TokenType::Register {
                    self.scanner.next();
                }
                if self.scanner.get_type() != TokenType::Eof {
                    let token = self.scanner.get_string().to_string();
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        "Additional arguments after instruction",
                        Some(&token),
                    );
                }
                return LineStatus::Ok;
            } else if cmp == std::cmp::Ordering::Greater {
                break;
            }
        }

        if mnemonic_found {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Instruction,
                "Wrong arguments for instruction",
                Some(&mnemonic),
            );
        }

        self.failure(
            LineStatus::Error,
            AsmErrorKind::Instruction,
            "No instruction with this name",
            Some(&mnemonic),
        )
    }

    fn store_arg_list(&mut self, size: usize) -> LineStatus {
        let mut more = true;
        while more {
            if self.scanner.get_type() == TokenType::String && self.scanner.token().len > 1 {
                let token = self.scanner.token();
                let buf = &token.bytes;
                let len = token.len;
                self.bytes.extend_from_slice(&buf[..len]);
                self.scanner.next();
            } else {
                let val = match self.evaluate_expression() {
                    Ok(value) => value,
                    Err(err) => return self.failure(LineStatus::Error, err.kind(), err.message(), None),
                };
                if size == 1 {
                    self.bytes.push((val & 0xff) as u8);
                } else {
                    self.bytes.push((val & 0xff) as u8);
                    self.bytes.push((val >> 8) as u8);
                }
            }
            more = self.scanner.get_type() == TokenType::Comma;
            self.scanner.next();
        }

        if self.scanner.get_type() != TokenType::Eof {
            let token = self.scanner.get_string().to_string();
            return self.failure(
                LineStatus::Warning,
                AsmErrorKind::Directive,
                "Found additional characters after expression list",
                Some(&token),
            );
        }
        LineStatus::Ok
    }
}

fn cmp_ignore_ascii_case(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase())
}

fn format_error(msg: &str, param: Option<&str>) -> String {
    match param {
        Some(p) => format!("{msg}: {p}"),
        None => msg.to_string(),
    }
}

struct ExprEvaluator<'a> {
    scanner: &'a mut Scanner,
    symbols: &'a SymbolTable,
    pass: u8,
    start_addr: u16,
}

impl<'a> ExprEvaluator<'a> {
    fn new(scanner: &'a mut Scanner, symbols: &'a SymbolTable, pass: u8, start_addr: u16) -> Self {
        Self {
            scanner,
            symbols,
            pass,
            start_addr,
        }
    }

    fn eval_expression(&mut self) -> Result<u32, AsmError> {
        self.eval_logical_or()
    }

    fn eval_atom(&mut self) -> Result<u32, AsmError> {
        let t = self.scanner.get_type();
        let mut val: u32;

        match t {
            TokenType::Error => {
                let msg = self.scanner.get_error_msg().to_string();
                return Err(AsmError {
                    kind: AsmErrorKind::Expression,
                    message: msg,
                });
            }
            TokenType::OpenParen => {
                self.scanner.next();
                val = self.eval_expression()?;
                if self.scanner.get_type() != TokenType::CloseParen {
                    let token = self.scanner.get_string().to_string();
                    return self.failure("Expecting close parenthesis, found", Some(&token));
                }
            }
            TokenType::Dollar => {
                val = self.start_addr as u32;
            }
            TokenType::Constant => {
                val = self.scanner.get_value() as u32;
            }
            TokenType::SumOper => {
                let op = self.scanner.get_value();
                match op {
                    x if x == TokenValue::Minus as i32 => {
                        self.scanner.next();
                        let inner = self.eval_atom()?;
                        return Ok(0u32.wrapping_sub(inner));
                    }
                    x if x == TokenValue::Plus as i32 => {
                        self.scanner.next();
                        return self.eval_atom();
                    }
                    _ => {
                        let token = self.scanner.get_string().to_string();
                        return self.failure("Expecting + or -, found", Some(&token));
                    }
                }
            }
            TokenType::BitNotOper => {
                self.scanner.next();
                let inner = self.eval_atom()?;
                return Ok(!inner);
            }
            TokenType::IsolateOper => {
                let op = self.scanner.get_value();
                self.scanner.next();
                let inner = self.eval_atom()?;
                if op == TokenValue::High as i32 {
                    return Ok((inner >> 8) & 0xff);
                }
                return Ok(inner & 0xff);
            }
            TokenType::LogicNotOper => {
                self.scanner.next();
                val = self.eval_relationals()?;
                return Ok(if (val & 0x01) != 0 { 0 } else { 0xffff });
            }
            TokenType::String => {
                let token = self.scanner.token();
                let len = token.len;
                let buf = &token.bytes;
                if len == 1 {
                    val = buf[0] as u32;
                } else if len == 2 {
                    val = ((buf[0] as u32) << 8) | (buf[1] as u32);
                } else {
                    return self.failure("Multi-character string not allowed in expression.", None);
                }
            }
            TokenType::Identifier | TokenType::Register => {
                let name = self.scanner.get_string().to_string();
                val = self.symbols.lookup(&name);
                if val == NO_ENTRY {
                    if self.pass > 1 {
                        return self.failure("Label not found", Some(&name));
                    }
                    val = 0;
                }
            }
            TokenType::LogicAndOper
            | TokenType::LogicOrOper
            | TokenType::BitAndOper
            | TokenType::BitOrOper
            | TokenType::FactorOper
            | TokenType::Conditional => {
                let name = self.scanner.get_string().to_string();
                let first = name.as_bytes().first().copied().unwrap_or(b'\0');
                if first.is_ascii_alphabetic() {
                    val = self.symbols.lookup(&name);
                    if val == NO_ENTRY {
                        if self.pass > 1 {
                            return self.failure("Label not found", Some(&name));
                        }
                        val = 0;
                    }
                } else {
                    let token = self.scanner.get_string().to_string();
                    return self.failure("Expected label or numeric constant, found", Some(&token));
                }
            }
            _ => {
                let token = self.scanner.get_string().to_string();
                return self.failure("Expected label or numeric constant, found", Some(&token));
            }
        }

        self.scanner.next();
        Ok(val)
    }

    fn eval_factors(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_atom()?;
        while self.scanner.get_type() == TokenType::FactorOper {
            let op = self.scanner.get_value();
            self.scanner.next();
            num1 &= 0xffff;
            let num2 = self.eval_atom()? & 0xffff;
            match op {
                v if v == TokenValue::Multiply as i32 => num1 = num1.wrapping_mul(num2),
                v if v == TokenValue::Divide as i32 => {
                    if num2 == 0 {
                        return self.failure("Divide by zero", None);
                    }
                    num1 /= num2;
                }
                v if v == TokenValue::Mod as i32 => num1 %= num2,
                v if v == TokenValue::Shl as i32 => num1 = num1.wrapping_shl(num2),
                v if v == TokenValue::Shr as i32 => num1 >>= num2,
                _ => {}
            }
        }
        Ok(num1)
    }

    fn eval_sums(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_factors()?;
        while self.scanner.get_type() == TokenType::SumOper {
            let op = self.scanner.get_value();
            self.scanner.next();
            let num2 = self.eval_factors()?;
            if op == TokenValue::Minus as i32 {
                num1 = num1.wrapping_sub(num2);
            } else {
                num1 = num1.wrapping_add(num2);
            }
        }
        Ok(num1)
    }

    fn eval_relationals(&mut self) -> Result<u32, AsmError> {
        let mut result = false;
        let mut num1 = self.eval_sums()?;
        if self.scanner.get_type() != TokenType::RelateOper {
            return Ok(num1);
        }
        let op = self.scanner.get_value();
        self.scanner.next();
        num1 &= 0xffff;
        let num2 = self.eval_sums()? & 0xffff;
        match op {
            v if v == TokenValue::Eq as i32 => result = num1 == num2,
            v if v == TokenValue::Ge as i32 => result = num1 >= num2,
            v if v == TokenValue::Gt as i32 => result = num1 > num2,
            v if v == TokenValue::Le as i32 => result = num1 <= num2,
            v if v == TokenValue::Lt as i32 => result = num1 < num2,
            v if v == TokenValue::Ne as i32 => result = num1 != num2,
            _ => {}
        }
        if result { Ok(0xffff) } else { Ok(0) }
    }

    fn eval_bitwise_and(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_relationals()?;
        while self.scanner.get_type() == TokenType::BitAndOper {
            self.scanner.next();
            let num2 = self.eval_relationals()?;
            num1 &= num2;
        }
        Ok(num1)
    }

    fn eval_bitwise_or(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_bitwise_and()?;
        while self.scanner.get_type() == TokenType::BitOrOper {
            let op = self.scanner.get_value();
            self.scanner.next();
            let num2 = self.eval_bitwise_and()?;
            if op == TokenValue::Or as i32 {
                num1 |= num2;
            } else {
                num1 ^= num2;
            }
        }
        Ok(num1)
    }

    fn eval_logical_and(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_bitwise_or()?;
        while self.scanner.get_type() == TokenType::LogicAndOper {
            self.scanner.next();
            let num2 = self.eval_bitwise_or()?;
            num1 = if (num1 & num2 & 0x01) != 0 { 0xffff } else { 0 };
        }
        Ok(num1)
    }

    fn eval_logical_or(&mut self) -> Result<u32, AsmError> {
        let mut num1 = self.eval_logical_and()?;
        while self.scanner.get_type() == TokenType::LogicOrOper {
            let op = self.scanner.get_value();
            self.scanner.next();
            let num2 = self.eval_logical_and()?;
            if op == TokenValue::Or as i32 {
                num1 = if ((num1 | num2) & 0x01) != 0 { 0xffff } else { 0 };
            } else {
                num1 = if ((num1 ^ num2) & 0x01) != 0 { 0xffff } else { 0 };
            }
        }
        Ok(num1)
    }

    fn failure(&mut self, msg: &str, param: Option<&str>) -> Result<u32, AsmError> {
        Err(AsmError::new(AsmErrorKind::Expression, msg, param))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        input_base_from_path, parse_bin_output_arg, parse_bin_range_str, resolve_bin_path,
        resolve_output_path, AsmError, AsmErrorKind, AsmLine, Assembler, BinRange, Cli, Diagnostic,
        LineStatus, ListingWriter, Severity,
    };
    use crate::preprocess::Preprocessor;
    use clap::Parser;
    use crate::symbol_table::{SymbolTable, NO_ENTRY};
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn process_line(
        asm: &mut AsmLine<'_>,
        line: &str,
        addr: u16,
        pass: u8,
    ) -> LineStatus {
        asm.process(line, 1, addr, pass)
    }

    fn assemble_example(asm_path: &Path, out_dir: &Path) -> Result<(), String> {
        let asm_name = asm_path.to_string_lossy().to_string();
        let base = asm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Invalid example filename".to_string())?;

        let list_path = out_dir.join(format!("{base}.lst"));
        let hex_path = out_dir.join(format!("{base}.hex"));

        let mut list_file =
            File::create(&list_path).map_err(|err| format!("Create list file: {err}"))?;
        let mut hex_file =
            File::create(&hex_path).map_err(|err| format!("Create hex file: {err}"))?;

        let mut pp = Preprocessor::new();
        pp.process_file(&asm_name)
            .map_err(|err| format!("Preprocess failed: {}", err.message()))?;
        let src_lines: Vec<String> = pp.lines().to_vec();

        let mut assembler = Assembler::new();
        assembler.clear_diagnostics();
        let _ = assembler.pass1(&src_lines);

        let mut listing = ListingWriter::new(&mut list_file, false);
        listing
            .header()
            .map_err(|err| format!("Write listing header: {err}"))?;
        let pass2 = assembler
            .pass2(&src_lines, &mut listing)
            .map_err(|err| format!("Pass2 failed: {err}"))?;
        listing
            .footer(&pass2, assembler.symbols(), assembler.image().num_entries())
            .map_err(|err| format!("Write listing footer: {err}"))?;

        assembler
            .image()
            .write_hex_file(&mut hex_file, None)
            .map_err(|err| format!("Write hex file: {err}"))?;

        Ok(())
    }

    fn diff_text(expected: &str, actual: &str) -> String {
        let expected_lines: Vec<&str> = expected.lines().collect();
        let actual_lines: Vec<&str> = actual.lines().collect();
        let min_len = expected_lines.len().min(actual_lines.len());

        let mut first_diff = 0usize;
        while first_diff < min_len && expected_lines[first_diff] == actual_lines[first_diff] {
            first_diff += 1;
        }

        if first_diff == min_len && expected_lines.len() == actual_lines.len() {
            return String::new();
        }

        let context = 3usize;
        let start = first_diff.saturating_sub(context);
        let end = (first_diff + context + 1).min(expected_lines.len().max(actual_lines.len()));

        let mut out = String::new();
        out.push_str(&format!("First difference at line {}\n", first_diff + 1));
        for idx in start..end {
            if let Some(line) = expected_lines.get(idx) {
                out.push_str(&format!("-{:5} {}\n", idx + 1, line));
            }
            if let Some(line) = actual_lines.get(idx) {
                out.push_str(&format!("+{:5} {}\n", idx + 1, line));
            }
        }

        if expected_lines.len() != actual_lines.len() {
            out.push_str(&format!(
                "Line count differs: expected {}, got {}\n",
                expected_lines.len(),
                actual_lines.len()
            ));
        }

        out
    }

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
        ]);
        assert_eq!(cli.infiles, vec![PathBuf::from("prog.asm")]);
        assert_eq!(cli.list_name, Some(String::new()));
        assert_eq!(cli.hex_name, Some(String::new()));
        assert_eq!(cli.outfile, Some("out".to_string()));
        assert_eq!(cli.bin_outputs, vec!["0000:ffff".to_string()]);
        assert_eq!(cli.fill_byte, Some("aa".to_string()));
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

    #[test]
    fn examples_match_reference_outputs() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let examples_dir = repo_root.join("examples");
        let reference_dir = examples_dir.join("reference");
        let update_reference = std::env::var("ASM485_UPDATE_REFERENCE").is_ok();

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let out_dir = repo_root.join("target").join(format!(
            "example-outputs-{}-{}",
            process::id(),
            nanos
        ));
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

            assemble_example(&asm_path, &out_dir)
                .unwrap_or_else(|err| panic!("Failed to assemble {base}: {err}"));

            let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
                .unwrap_or_else(|err| panic!("Missing output listing for {base}: {err}"));
            let out_lst_text = String::from_utf8_lossy(&out_lst);
            let ref_lst_path = reference_dir.join(format!("{base}.lst"));
            if update_reference {
                fs::write(&ref_lst_path, &out_lst).unwrap_or_else(|err| {
                    panic!("Failed to write reference listing {}: {err}", ref_lst_path.display())
                });
            } else {
                let ref_lst = fs::read(&ref_lst_path).unwrap_or_else(|err| {
                    panic!("Missing reference listing {}: {err}", ref_lst_path.display())
                });
                let ref_lst_text = String::from_utf8_lossy(&ref_lst);
                if out_lst_text != ref_lst_text {
                    let diff = diff_text(&ref_lst_text, &out_lst_text);
                    panic!("Listing mismatch for {base}\n{diff}");
                }
            }

            let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
                .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
            let ref_hex_path = reference_dir.join(format!("{base}.hex"));
            if update_reference {
                fs::write(&ref_hex_path, &out_hex).unwrap_or_else(|err| {
                    panic!("Failed to write reference hex {}: {err}", ref_hex_path.display())
                });
            } else {
                let ref_hex = fs::read(&ref_hex_path).unwrap_or_else(|err| {
                    panic!("Missing reference hex {}: {err}", ref_hex_path.display())
                });
                assert_eq!(out_hex, ref_hex, "Hex mismatch for {base}");
            }
        }
    }

    #[test]
    fn org_sets_address() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    ORG 1000h", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.start_addr(), 0x1000);
        assert_eq!(asm.aux_value(), 0x1000);
    }

    #[test]
    fn ds_reserves_space_and_defines_label() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "BUFFER: DS 4", 0x0200, 1);
        assert_eq!(status, LineStatus::DirDs);
        assert_eq!(asm.aux_value(), 4);
        assert_eq!(asm.symbols().lookup("BUFFER"), 0x0200);
    }

    #[test]
    fn db_and_dw_emit_bytes() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DB 1, 2, 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 2, 3]);

        let status = process_line(&mut asm, "    DW 7", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);
    }

    #[test]
    fn equ_defines_symbol_for_pass2() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "VAL EQU 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), 3);

        let status = process_line(&mut asm, "    DW VAL+1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[4, 0]);
    }

    #[test]
    fn instruction_encoding_mvi() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    MVI A, 12h", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x3e, 0x12]);
    }

    #[test]
    fn conditionals_do_not_skip_mnemonic_lines() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    IF 0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_skipping());

        let status = process_line(&mut asm, "    DB 5", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[5]);
    }

    #[test]
    fn undefined_label_in_pass2_errors() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW MISSING", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.symbols().lookup("MISSING"), NO_ENTRY);
    }

    #[test]
    fn expression_precedence_and_ops() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW 1+2*3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);

        let status = process_line(&mut asm, "    DW (1+2)*3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[9, 0]);

        let status = process_line(&mut asm, "    DW 1 SHL 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x10, 0x00]);

        let status = process_line(&mut asm, "    DW 1 | 2", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3, 0]);
    }

    #[test]
    fn logical_ops_use_lsb_only() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW 2 AND 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x00, 0x00]);

        let status = process_line(&mut asm, "    DW 7 AND 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0xff, 0xff]);

        let status = process_line(&mut asm, "    DW NOT 0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0xff, 0xff]);
    }

    #[test]
    fn conditional_nesting_state_changes() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    IF 0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_skipping());

        let status = process_line(&mut asm, "    ELSE", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(!asm.cond_skipping());

        let status = process_line(&mut asm, "    ENDIF", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_is_empty());
    }

    #[test]
    fn expression_high_low_and_unary() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW HIGH 1234H", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x12, 0x00]);

        let status = process_line(&mut asm, "    DW LOW 1234H", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x34, 0x00]);

        let status = process_line(&mut asm, "    DW -1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0xff, 0xff]);
    }

    #[test]
    fn expression_current_address_dollar() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW $ + 1", 0x1000, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x10]);
    }

    #[test]
    fn conditional_errors_for_mismatched_blocks() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    ELSE", 0, 2);
        assert_eq!(status, LineStatus::Error);

        let status = process_line(&mut asm, "    ENDIF", 0, 2);
        assert_eq!(status, LineStatus::Error);
    }

    #[test]
    fn column_one_errors_for_identifier() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "mov a,b", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert!(asm.error_message().contains("column 1"));
    }

    #[test]
    fn error_kind_for_scanner_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "123", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Scanner);
    }

    #[test]
    fn error_kind_for_directive_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    EQU 5", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn error_kind_for_instruction_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    RST A", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    }

    #[test]
    fn error_kind_for_expression_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    DW 1/0", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Expression);
    }

    #[test]
    fn error_kind_for_symbol_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "LABEL: NOP", 0, 1);
        assert_eq!(status, LineStatus::Ok);

        let status = process_line(&mut asm, "LABEL: NOP", 1, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Symbol);
    }

    #[test]
    fn diagnostic_format_includes_line_and_severity() {
        let err = AsmError::new(AsmErrorKind::Assembler, "Bad thing", None);
        let diag = Diagnostic::new(12, Severity::Error, err);
        assert_eq!(diag.format(), "12: ERROR - Bad thing");
    }
}
