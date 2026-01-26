// Assembler core pipeline and listing/output generation.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};

use crate::imagestore::ImageStore;
use crate::instructions::table::INSTRUCTION_TABLE;
use crate::instructions::ArgType;
use crate::parser::{AssignOp, BinaryOp, Expr, Label, LineAst, ParseError, UnaryOp};
use crate::parser as asm_parser;
use crate::parser_reporter::{format_parse_error, format_parse_error_listing};
use crate::preprocess::Preprocessor;
use crate::token_value::TokenValue;
use crate::symbol_table::{SymbolTable, NO_ENTRY};
use crate::tokenizer::{ConditionalKind, Span};

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
            u8::from_str_radix(fill, 16).unwrap_or(0xff)
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
        if let Err(err) = assembler.image().write_hex_file(&mut hex_file, go_addr) {
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

fn input_base_from_path(path: &Path) -> Result<(String, String), AsmRunError> {
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
    Parser,
    Preprocess,
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
    parser_error: Option<ParseError>,
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
            parser_error: None,
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

    fn with_parser_error(mut self, parser_error: Option<ParseError>) -> Self {
        self.parser_error = parser_error;
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
        if let Some(parser_error) = &self.parser_error {
            return format_parse_error(parser_error, self.file.as_deref(), lines, use_color);
        }
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
        asm_line.clear_scopes();
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
                            .with_column(asm_line.error_column())
                            .with_parser_error(asm_line.parser_error()),
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
                "Found .if without .endif in pass 1",
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
        asm_line.clear_scopes();
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
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                        listing.write_diagnostic(
                            "ERROR",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                            asm_line.parser_error_ref(),
                        )?;
                    }
                    counts.errors += 1;
                }
                LineStatus::Warning => {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Warning, err.clone())
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                        listing.write_diagnostic(
                            "WARNING",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                            asm_line.parser_error_ref(),
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
            let err = AsmError::new(AsmErrorKind::Conditional, "Found .if without .endif", None);
            diagnostics.push(Diagnostic::new(line_num, Severity::Error, err.clone()));
            listing.write_diagnostic("ERROR", err.message(), line_num, None, lines, None)?;
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
        parser_error: Option<&ParseError>,
    ) -> std::io::Result<()> {
        if let Some(parser_error) = parser_error {
            let formatted = format_parse_error_listing(parser_error, Some(source_lines), true);
            for line in formatted.lines() {
                writeln!(self.out, "{line}")?;
            }
            return Ok(());
        }

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
    #[allow(dead_code)]
    Warning = 5,
    Error = 6,
    Pass1Error = 7,
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

struct ScopeFrame {
    segment_count: usize,
}

struct ScopeStack {
    segments: Vec<String>,
    frames: Vec<ScopeFrame>,
    anon_counter: u32,
}

impl ScopeStack {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
            frames: Vec::new(),
            anon_counter: 0,
        }
    }

    fn clear(&mut self) {
        self.segments.clear();
        self.frames.clear();
        self.anon_counter = 0;
    }

    fn depth(&self) -> usize {
        self.segments.len()
    }

    fn prefix(&self, depth: usize) -> String {
        self.segments[..depth].join(".")
    }

    fn qualify(&self, name: &str) -> String {
        if self.segments.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.segments.join("."), name)
        }
    }

    fn push_named(&mut self, name: &str) -> Result<(), &'static str> {
        if name.is_empty() {
            return Err("Scope name cannot be empty");
        }
        let parts: Vec<&str> = name.split('.').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err("Scope name cannot contain empty segments");
        }
        for part in &parts {
            self.segments.push((*part).to_string());
        }
        self.frames.push(ScopeFrame {
            segment_count: parts.len(),
        });
        Ok(())
    }

    fn push_anonymous(&mut self) {
        self.anon_counter = self.anon_counter.saturating_add(1);
        let name = format!("__scope{}", self.anon_counter);
        self.segments.push(name);
        self.frames.push(ScopeFrame { segment_count: 1 });
    }

    fn pop(&mut self) -> bool {
        let Some(frame) = self.frames.pop() else {
            return false;
        };
        for _ in 0..frame.segment_count {
            self.segments.pop();
        }
        true
    }
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
    scope_stack: ScopeStack,
    last_error: Option<AsmError>,
    last_error_column: Option<usize>,
    last_parser_error: Option<ParseError>,
    line_end_span: Option<Span>,
    line_end_token: Option<String>,
    bytes: Vec<u8>,
    start_addr: u16,
    aux_value: u16,
    pass: u8,
    label: Option<String>,
    mnemonic: Option<String>,
}

struct AstEvalError {
    error: AsmError,
    span: Span,
}

impl<'a> AsmLine<'a> {
    fn new(symbols: &'a mut SymbolTable) -> Self {
        Self {
            symbols,
            cond_stack: ConditionalStack::new(),
            scope_stack: ScopeStack::new(),
            last_error: None,
            last_error_column: None,
            last_parser_error: None,
            line_end_span: None,
            line_end_token: None,
            bytes: Vec::with_capacity(256),
            start_addr: 0,
            aux_value: 0,
            pass: 1,
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

    fn parser_error(&self) -> Option<ParseError> {
        self.last_parser_error.clone()
    }

    fn parser_error_ref(&self) -> Option<&ParseError> {
        self.last_parser_error.as_ref()
    }

    fn missing_expr_info(&self) -> (Span, Option<String>) {
        let span = self.line_end_span.unwrap_or(Span {
            line: 0,
            col_start: 1,
            col_end: 1,
        });
        let token = self.line_end_token.clone();
        (span, token)
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

    fn clear_scopes(&mut self) {
        self.scope_stack.clear();
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

    fn scoped_define_name(&self, name: &str) -> String {
        if name.contains('.') {
            name.to_string()
        } else {
            self.scope_stack.qualify(name)
        }
    }

    fn resolve_scoped_name(&self, name: &str) -> Option<String> {
        if name.contains('.') {
            return self
                .symbols
                .entry(name)
                .map(|_| name.to_string());
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if self.symbols.entry(&candidate).is_some() {
                return Some(candidate);
            }
            depth = depth.saturating_sub(1);
        }
        if self.symbols.entry(name).is_some() {
            Some(name.to_string())
        } else {
            None
        }
    }

    fn lookup_scoped_value(&self, name: &str) -> Option<u32> {
        if name.contains('.') {
            return self.symbols.entry(name).map(|entry| entry.val);
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if let Some(entry) = self.symbols.entry(&candidate) {
                return Some(entry.val);
            }
            depth = depth.saturating_sub(1);
        }
        self.symbols.entry(name).map(|entry| entry.val)
    }

    fn process(
        &mut self,
        line: &str,
        line_num: u32,
        addr: u16,
        pass: u8,
    ) -> LineStatus {
        self.last_error = None;
        self.last_error_column = None;
        self.last_parser_error = None;
        self.line_end_span = None;
        self.line_end_token = None;
        self.start_addr = addr;
        self.pass = pass;
        self.bytes.clear();
        self.aux_value = 0;

        self.label = None;
        self.mnemonic = None;

        match asm_parser::Parser::from_line(line, line_num) {
            Ok(mut parser) => {
                self.line_end_span = Some(parser.end_span());
                self.line_end_token = parser.end_token_text().map(|s| s.to_string());
                match parser.parse_line() {
                    Ok(ast) => self.process_ast(ast),
                    Err(err) => {
                        self.last_error =
                            Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                        self.last_error_column = Some(err.span.col_start);
                        self.last_parser_error = Some(err);
                        LineStatus::Error
                    }
                }
            }
            Err(err) => {
                self.last_error = Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.last_error_column = Some(err.span.col_start);
                self.last_parser_error = Some(err);
                LineStatus::Error
            }
        }
    }

    fn process_ast(&mut self, ast: LineAst) -> LineStatus {
        match ast {
            LineAst::Empty => LineStatus::NothingDone,
            LineAst::Conditional { kind, expr, span } => {
                self.process_conditional_ast(kind, expr.as_ref(), span)
            }
            LineAst::Assignment { label, op, expr, span } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.process_assignment_ast(&label, op, &expr, span)
            }
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
                self.label = label.as_ref().map(|l| l.name.clone());
                self.mnemonic = mnemonic.clone();

                if self.cond_stack.skipping() {
                    if let Some(name) = mnemonic.as_deref() {
                        if is_scope_directive(name) {
                            return self.process_directive_ast(name, &operands);
                        }
                    }
                    return LineStatus::Skip;
                }

                let mnemonic = match mnemonic {
                    Some(m) => m,
                    None => {
                        if let Some(label) = &label {
                            let full_name = self.scoped_define_name(&label.name);
                            let res = if self.pass == 1 {
                                self.symbols.add(&full_name, self.start_addr as u32, false)
                            } else {
                                self.symbols.update(&full_name, self.start_addr as u32)
                            };
                            if res == crate::symbol_table::SymbolTableResult::Duplicate {
                                return self.failure_at_span(
                                    LineStatus::Error,
                                    AsmErrorKind::Symbol,
                                    "Symbol defined more than once",
                                    Some(&label.name),
                                    label.span,
                                );
                            }
                        }
                        return LineStatus::NothingDone;
                    }
                };

                if let Some(label) = &label {
                    if !is_symbol_assignment_directive(&mnemonic) {
                        let full_name = self.scoped_define_name(&label.name);
                        let res = if self.pass == 1 {
                            self.symbols.add(&full_name, self.start_addr as u32, false)
                        } else {
                            self.symbols.update(&full_name, self.start_addr as u32)
                        };
                        if res == crate::symbol_table::SymbolTableResult::Duplicate {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Symbol,
                                "Symbol defined more than once",
                                Some(&label.name),
                                label.span,
                            );
                        }
                    }
                }

                let mut status = self.process_directive_ast(&mnemonic, &operands);
                if status == LineStatus::NothingDone {
                    status = self.process_instruction_ast(&mnemonic, &operands);
                }
                status
            }
        }
    }

    fn process_conditional_ast(
        &mut self,
        kind: ConditionalKind,
        expr: Option<&Expr>,
        span: Span,
    ) -> LineStatus {
        let skipping = self.cond_stack.skipping();

        match kind {
            ConditionalKind::If => {
                let val = expr
                    .and_then(|expr| self.eval_expr_ast(expr).ok())
                    .unwrap_or(0);
                if skipping {
                    if let Some(ctx) = self.cond_stack.last_mut() {
                        ctx.skip_level = ctx.skip_level.saturating_add(1);
                    }
                    return LineStatus::Skip;
                }
                let prev = self.cond_stack.last();
                let mut ctx = ConditionalContext::new(prev);
                if val != 0 {
                    ctx.matched = true;
                } else {
                    ctx.skipping = true;
                }
                self.cond_stack.push(ctx);
            }
            ConditionalKind::Else | ConditionalKind::ElseIf => {
                if self.cond_stack.is_empty() {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr.map(expr_span).unwrap_or(span)
                    } else {
                        self.line_end_span.unwrap_or(span)
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif found without matching .if",
                        None,
                        err_span,
                    );
                }
                let skip_level = self
                    .cond_stack
                    .last()
                    .map(|ctx| ctx.skip_level)
                    .unwrap_or(0);
                if skip_level > 0 {
                    return LineStatus::Skip;
                }
                let val = if kind == ConditionalKind::Else {
                    1
                } else {
                    expr.and_then(|expr| self.eval_expr_ast(expr).ok())
                        .unwrap_or(0)
                };
                let ctx = self.cond_stack.last_mut().unwrap();
                if ctx.sub_type == TokenValue::Else as i32 {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr.map(expr_span).unwrap_or(span)
                    } else {
                        self.line_end_span.unwrap_or(span)
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif cannot follow .else",
                        None,
                        err_span,
                    );
                }
                let sub_type = if kind == ConditionalKind::Else {
                    TokenValue::Else as i32
                } else {
                    TokenValue::ElseIf as i32
                };
                if !ctx.skipping {
                    ctx.skipping = true;
                    ctx.sub_type = sub_type;
                } else if !ctx.matched && val != 0 {
                    ctx.matched = true;
                    ctx.skipping = false;
                    ctx.sub_type = sub_type;
                }
            }
            ConditionalKind::EndIf => {
                if self.cond_stack.is_empty() {
                    let err_span = self.line_end_span.unwrap_or(span);
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endif found without matching .if",
                        None,
                        err_span,
                    );
                }
                let ctx = self.cond_stack.last_mut().unwrap();
                if ctx.skip_level > 0 {
                    ctx.skip_level = ctx.skip_level.saturating_sub(1);
                    return LineStatus::Skip;
                }
                self.cond_stack.pop();
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
            }
        }

        LineStatus::Ok
    }

    fn process_directive_ast(&mut self, mnemonic: &str, operands: &[Expr]) -> LineStatus {
        let upper = mnemonic.to_ascii_uppercase();
        let had_dot = upper.starts_with('.');
        let directive = upper.strip_prefix('.').unwrap_or(&upper);
        if !had_dot {
            return LineStatus::NothingDone;
        }
        match directive {
            "BLOCK" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .block",
                        None,
                    );
                }
                if let Some(label) = self.label.clone() {
                    if let Err(message) = self.scope_stack.push_named(&label) {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            message,
                            Some(&label),
                        );
                    }
                } else {
                    self.scope_stack.push_anonymous();
                }
                LineStatus::Ok
            }
            "ENDBLOCK" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endblock",
                        None,
                    );
                }
                if !self.scope_stack.pop() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endblock found without matching .block",
                        None,
                    );
                }
                LineStatus::Ok
            }
            "ORG" => {
                let expr = match operands.first() {
                    Some(expr) => expr,
                    None => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Missing expression for ORG",
                            None,
                        )
                    }
                };
                let val = match self.eval_expr_ast(expr) {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        )
                    }
                };
                self.start_addr = val as u16;
                self.aux_value = val as u16;
                LineStatus::DirEqu
            }
            "CONST" | "VAR" | "SET" => {
                if self.label.is_none() {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Must specify symbol before .const/.var/.set",
                        None,
                        Some(1),
                    );
                }
                let expr = match operands.first() {
                    Some(expr) => expr,
                    None => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Missing expression for .const/.var/.set",
                            None,
                        )
                    }
                };
                let is_rw = directive == "SET" || directive == "VAR";
                let val = match self.eval_expr_ast(expr) {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        )
                    }
                };
                let label = self.label.clone().unwrap_or_default();
                let full_name = self.scoped_define_name(&label);
                let res = if self.pass == 1 {
                    self.symbols.add(&full_name, val, is_rw)
                } else {
                    self.symbols.update(&full_name, val)
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
            "BYTE" => self.store_arg_list_ast(operands, 1),
            "WORD" => self.store_arg_list_ast(operands, 2),
            "DS" => {
                let expr = match operands.first() {
                    Some(expr) => expr,
                    None => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Missing expression for DS",
                            None,
                        )
                    }
                };
                let val = match self.eval_expr_ast(expr) {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        )
                    }
                };
                self.aux_value = val as u16;
                LineStatus::DirDs
            }
            "END" => LineStatus::Ok,
            "CPU" => {
                let expr = match operands.first() {
                    Some(expr) => expr,
                    None => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unsupported CPU type, must be 8085 or 8080",
                            None,
                        )
                    }
                };
                let cpu = match expr {
                    Expr::Number(text, _) => text.clone(),
                    Expr::Identifier(name, _) => name.clone(),
                    _ => String::new(),
                };
                if cpu != "8085" && cpu != "8080" {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unsupported CPU type, must be 8085 or 8080",
                        Some(&cpu),
                    );
                }
                LineStatus::Ok
            }
            _ => LineStatus::NothingDone,
        }
    }

    fn process_assignment_ast(
        &mut self,
        label: &Label,
        op: AssignOp,
        expr: &Expr,
        span: Span,
    ) -> LineStatus {
        self.label = Some(label.name.clone());

        match op {
            AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef => {
                let full_name = self.scoped_define_name(&label.name);
                if op == AssignOp::VarIfUndef {
                    if let Some(entry) = self.symbols.entry(&full_name) {
                        self.aux_value = entry.val as u16;
                        return LineStatus::DirEqu;
                    }
                }
                let val = match self.eval_expr_ast(expr) {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        )
                    }
                };
                let is_rw = op != AssignOp::Const;
                let res = if self.pass == 1 {
                    self.symbols.add(&full_name, val, is_rw)
                } else {
                    self.symbols.update(&full_name, val)
                };
                if res == crate::symbol_table::SymbolTableResult::Duplicate {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "symbol has already been defined",
                        Some(&label.name),
                        Some(1),
                    );
                } else if res == crate::symbol_table::SymbolTableResult::TableFull {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "could not add symbol, table full",
                        Some(&label.name),
                        Some(1),
                    );
                }
                self.aux_value = val as u16;
                return LineStatus::DirEqu;
            }
            _ => {}
        }

        let target = match self.resolve_scoped_name(&label.name) {
            Some(name) => name,
            None => {
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Symbol,
                    "symbol has not been defined",
                    Some(&label.name),
                    Some(1),
                )
            }
        };
        let (left_val, is_rw) = match self.symbols.entry(&target) {
            Some(entry) => (entry.val, entry.rw),
            None => {
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Symbol,
                    "symbol has not been defined",
                    Some(&label.name),
                    Some(1),
                )
            }
        };

        if !is_rw {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "symbol is read-only",
                Some(&label.name),
                Some(1),
            );
        }

        let rhs = match self.eval_expr_ast(expr) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        let new_val = match self.apply_assignment_op(op, left_val, rhs, span) {
            Ok(val) => val,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };

        if let Some(entry) = self.symbols.entry_mut(&target) {
            entry.val = new_val;
            entry.updated = true;
        }
        self.aux_value = new_val as u16;
        LineStatus::DirEqu
    }

    fn process_instruction_ast(&mut self, mnemonic: &str, operands: &[Expr]) -> LineStatus {
        let upper = mnemonic.to_ascii_uppercase();

        if upper == "RST" {
            let arg = match operands.first() {
                Some(expr) => expr,
                None => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        "RST instruction argument must be 0-7",
                        None,
                    )
                }
            };
            let arg_text = expr_text(arg).unwrap_or_default();
            let is_number = matches!(arg, Expr::Number(_, _));
            if let Expr::Binary { op, left, span, .. } = arg {
                if let Expr::Number(text, _) = &**left {
                    if text.len() == 1 && matches!(text.as_bytes().first(), Some(b'0'..=b'7')) {
                        let val = text.as_bytes()[0] - b'0';
                        self.bytes.push(0xc7 | (val << 3));
                        let op_text = binary_op_text(*op);
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            "Found extra arguments after RST instruction",
                            Some(op_text),
                            *span,
                        );
                    }
                }
            }
            if !is_number
                || arg_text.len() != 1
                || !matches!(arg_text.as_bytes().first(), Some(b'0'..=b'7'))
            {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    "RST instruction argument must be 0-7",
                    Some(&arg_text),
                    expr_span(arg),
                );
            }
            let val = arg_text.as_bytes()[0] - b'0';
            self.bytes.push(0xc7 | (val << 3));
            if operands.len() > 1 {
                let extra = operands.get(1).unwrap();
                let span = expr_span(extra);
                let extra_text = expr_text(extra).unwrap_or_default();
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    "Found extra arguments after RST instruction",
                    Some(&extra_text),
                    span,
                );
            }
            return LineStatus::Ok;
        }

        let mut regs = Vec::new();
        let mut reg_spans = Vec::new();
        for expr in operands.iter().take(2) {
            if let Expr::Register(name, span) = expr {
                regs.push(name.clone());
                reg_spans.push(*span);
            } else {
                break;
            }
        }
        let num_regs = regs.len();

        let mut mnemonic_found = false;
        for inst in INSTRUCTION_TABLE {
            let cmp = cmp_ignore_ascii_case(inst.mnemonic, mnemonic);
            if cmp == std::cmp::Ordering::Equal {
                mnemonic_found = true;
                let mut effective_num_regs = num_regs as i32;
                let mut expr_index = num_regs;
                if inst.arg_type != ArgType::None && inst.num_regs as i32 == num_regs as i32 - 1 {
                    effective_num_regs -= 1;
                    expr_index = effective_num_regs as usize;
                } else if inst.num_regs as i32 != num_regs as i32 {
                    let span = operands
                        .get(num_regs)
                        .map(expr_span)
                        .or_else(|| reg_spans.last().copied())
                        .unwrap_or(Span {
                            line: 0,
                            col_start: 1,
                            col_end: 1,
                        });
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        "Wrong number of register arguments for instruction",
                        Some(mnemonic),
                        span,
                    );
                }

                let mut effective_regs = regs.clone();
                effective_regs.truncate(effective_num_regs.max(0) as usize);

                if inst.num_regs >= 1
                    && effective_regs
                        .first()
                        .map(|r| !inst.reg1.eq_ignore_ascii_case(r))
                        .unwrap_or(true)
                {
                    continue;
                }
                if inst.num_regs == 2
                    && effective_regs
                        .get(1)
                        .map(|r| !inst.reg2.eq_ignore_ascii_case(r))
                        .unwrap_or(true)
                {
                    continue;
                }

                self.bytes.push(inst.opcode);
                if inst.arg_type != ArgType::None {
                    let expr = match operands.get(expr_index) {
                        Some(expr) => expr,
                        None => {
                            let (span, token) = self.missing_expr_info();
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Expression,
                                "Expected label or numeric constant, found",
                                token.as_deref(),
                                span,
                            );
                        }
                    };
                    let val = match self.eval_expr_ast(expr) {
                        Ok(value) => value,
                        Err(err) => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                err.error.kind(),
                                err.error.message(),
                                None,
                                err.span,
                            )
                        }
                    };
                    self.bytes.push((val & 0xff) as u8);
                    if inst.arg_type == ArgType::Word {
                        self.bytes.push((val >> 8) as u8);
                    }
                }

                let expected = effective_num_regs as usize
                    + if inst.arg_type == ArgType::None { 0 } else { 1 };
                if operands.len() > expected {
                    let extra = operands.get(expected).unwrap();
                    let span = expr_span(extra);
                    let extra_text = expr_text(extra).unwrap_or_default();
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        "Additional arguments after instruction",
                        Some(&extra_text),
                        span,
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
                Some(mnemonic),
            );
        }

        self.failure(
            LineStatus::Error,
            AsmErrorKind::Instruction,
            "No instruction with this name",
            Some(mnemonic),
        )
    }

    fn store_arg_list_ast(&mut self, operands: &[Expr], size: usize) -> LineStatus {
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing expression in data list",
                None,
            );
        }

        for expr in operands {
            if let Expr::String(bytes, span) = expr {
                if bytes.len() > 1 {
                    self.bytes.extend_from_slice(bytes);
                    continue;
                }
                if bytes.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Empty string not allowed in expression list",
                        None,
                        *span,
                    );
                }
            }
            let val = match self.eval_expr_ast(expr) {
                Ok(value) => value,
                Err(err) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        err.error.kind(),
                        err.error.message(),
                        None,
                        err.span,
                    )
                }
            };
            if size == 1 {
                self.bytes.push((val & 0xff) as u8);
            } else {
                self.bytes.push((val & 0xff) as u8);
                self.bytes.push((val >> 8) as u8);
            }
        }

        LineStatus::Ok
    }

    fn apply_assignment_op(
        &self,
        op: AssignOp,
        left: u32,
        right: u32,
        span: Span,
    ) -> Result<u32, AstEvalError> {
        let val = match op {
            AssignOp::Add => left.wrapping_add(right),
            AssignOp::Sub => left.wrapping_sub(right),
            AssignOp::Mul => left.wrapping_mul(right),
            AssignOp::Div => {
                if right == 0 {
                    return Err(AstEvalError {
                        error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                        span,
                    });
                }
                left / right
            }
            AssignOp::Mod => {
                if right == 0 {
                    return Err(AstEvalError {
                        error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                        span,
                    });
                }
                left % right
            }
            AssignOp::Pow => left.wrapping_pow(right),
            AssignOp::BitOr => left | right,
            AssignOp::BitXor => left ^ right,
            AssignOp::BitAnd => left & right,
            AssignOp::LogicOr => {
                if left != 0 || right != 0 { 1 } else { 0 }
            }
            AssignOp::LogicAnd => {
                if left != 0 && right != 0 { 1 } else { 0 }
            }
            AssignOp::Shl => {
                let shift = right & 0x1f;
                left.wrapping_shl(shift)
            }
            AssignOp::Shr => {
                let shift = right & 0x1f;
                left >> shift
            }
            AssignOp::Concat => concat_values(left, right),
            AssignOp::Min => left.min(right),
            AssignOp::Max => left.max(right),
            AssignOp::Repeat => repeat_value(left, right),
            AssignOp::Member => right,
            AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef => right,
        };
        Ok(val)
    }

    fn eval_expr_ast(&self, expr: &Expr) -> Result<u32, AstEvalError> {
        match expr {
            Expr::Error(message, span) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, message, None),
                span: *span,
            }),
            Expr::Number(text, span) => parse_number_text(text, *span),
            Expr::Identifier(name, span) | Expr::Register(name, span) => {
                let val = match self.lookup_scoped_value(name) {
                    Some(value) => value,
                    None => NO_ENTRY,
                };
                if val == NO_ENTRY {
                    if self.pass > 1 {
                        return Err(AstEvalError {
                            error: AsmError::new(AsmErrorKind::Expression, "Label not found", Some(name)),
                            span: *span,
                        });
                    }
                    return Ok(0);
                }
                Ok(val)
            }
            Expr::Dollar(_span) => Ok(self.start_addr as u32),
            Expr::String(bytes, span) => {
                if bytes.len() == 1 {
                    Ok(bytes[0] as u32)
                } else if bytes.len() == 2 {
                    Ok(((bytes[0] as u32) << 8) | (bytes[1] as u32))
                } else {
                    Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Multi-character string not allowed in expression.",
                            None,
                        ),
                        span: *span,
                    })
                }
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                let cond_val = self.eval_expr_ast(cond)?;
                let then_val = self.eval_expr_ast(then_expr)?;
                let else_val = self.eval_expr_ast(else_expr)?;
                if cond_val != 0 {
                    Ok(then_val)
                } else {
                    Ok(else_val)
                }
            }
            Expr::Unary { op, expr, span: _ } => {
                let inner = self.eval_expr_ast(expr)?;
                let val = match op {
                    UnaryOp::Plus => inner,
                    UnaryOp::Minus => 0u32.wrapping_sub(inner),
                    UnaryOp::BitNot => !inner,
                    UnaryOp::LogicNot => {
                        if inner != 0 { 0 } else { 1 }
                    }
                    UnaryOp::High => (inner >> 8) & 0xff,
                    UnaryOp::Low => inner & 0xff,
                };
                Ok(val)
            }
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => {
                let left_val = self.eval_expr_ast(left)?;
                let right_val = self.eval_expr_ast(right)?;
                let val = match op {
                    BinaryOp::Multiply => left_val.wrapping_mul(right_val),
                    BinaryOp::Divide => {
                        if right_val == 0 {
                            let span = self.line_end_span.unwrap_or(*span);
                            return Err(AstEvalError {
                                error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                                span,
                            });
                        }
                        left_val / right_val
                    }
                    BinaryOp::Mod => {
                        if right_val == 0 {
                            let span = self.line_end_span.unwrap_or(*span);
                            return Err(AstEvalError {
                                error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                                span,
                            });
                        }
                        left_val % right_val
                    }
                    BinaryOp::Power => left_val.wrapping_pow(right_val),
                    BinaryOp::Shl => {
                        let shift = right_val & 0x1f;
                        left_val.wrapping_shl(shift)
                    }
                    BinaryOp::Shr => {
                        let shift = right_val & 0x1f;
                        left_val >> shift
                    }
                    BinaryOp::Add => left_val.wrapping_add(right_val),
                    BinaryOp::Subtract => left_val.wrapping_sub(right_val),
                    BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Ge
                    | BinaryOp::Gt
                    | BinaryOp::Le
                    | BinaryOp::Lt => {
                        let result = match op {
                            BinaryOp::Eq => left_val == right_val,
                            BinaryOp::Ne => left_val != right_val,
                            BinaryOp::Ge => left_val >= right_val,
                            BinaryOp::Gt => left_val > right_val,
                            BinaryOp::Le => left_val <= right_val,
                            BinaryOp::Lt => left_val < right_val,
                            _ => false,
                        };
                        if result { 1 } else { 0 }
                    }
                    BinaryOp::BitAnd => left_val & right_val,
                    BinaryOp::BitOr => left_val | right_val,
                    BinaryOp::BitXor => left_val ^ right_val,
                    BinaryOp::LogicAnd => {
                        if left_val != 0 && right_val != 0 { 1 } else { 0 }
                    }
                    BinaryOp::LogicOr => {
                        if left_val != 0 || right_val != 0 { 1 } else { 0 }
                    }
                    BinaryOp::LogicXor => {
                        let left_true = left_val != 0;
                        let right_true = right_val != 0;
                        if left_true ^ right_true { 1 } else { 0 }
                    }
                };
                Ok(val)
            }
        }
    }

    fn failure_at_span(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        span: Span,
    ) -> LineStatus {
        self.failure_at(status, kind, msg, param, Some(span.col_start))
    }

    fn failure(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
    ) -> LineStatus {
        let column = self.line_end_span.map(|span| span.col_start);
        self.failure_at(status, kind, msg, param, column)
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

}

fn cmp_ignore_ascii_case(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase())
}

fn is_symbol_assignment_directive(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        ".CONST" | ".VAR" | ".SET"
    )
}

fn is_scope_directive(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        ".BLOCK" | ".ENDBLOCK"
    )
}

fn concat_values(left: u32, right: u32) -> u32 {
    let width = if right == 0 {
        1
    } else {
        (32 - right.leading_zeros()).div_ceil(8).min(4)
    };
    let shift = (width * 8).min(32);
    let mask = if shift >= 32 {
        u64::MAX
    } else {
        (1u64 << shift) - 1
    };
    let combined = ((left as u64) << shift) | ((right as u64) & mask);
    combined as u32
}

fn repeat_value(left: u32, right: u32) -> u32 {
    let count = right.min(4);
    let byte = left & 0xff;
    let mut result = 0u32;
    for _ in 0..count {
        result = (result << 8) | byte;
    }
    result
}

fn expr_span(expr: &Expr) -> Span {
    match expr {
        Expr::Number(_, span)
        | Expr::Identifier(_, span)
        | Expr::Register(_, span)
        | Expr::Dollar(span)
        | Expr::String(_, span)
        | Expr::Error(_, span) => *span,
        Expr::Unary { span, .. } | Expr::Binary { span, .. } | Expr::Ternary { span, .. } => *span,
    }
}

fn expr_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Number(text, _) => Some(text.clone()),
        Expr::Identifier(name, _) | Expr::Register(name, _) => Some(name.clone()),
        Expr::Dollar(_) => Some("$".to_string()),
        Expr::String(_, _) => Some("<string>".to_string()),
        Expr::Error(_, _) => None,
        Expr::Unary { .. } | Expr::Binary { .. } | Expr::Ternary { .. } => None,
    }
}

fn binary_op_text(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Subtract => "-",
        BinaryOp::Multiply => "*",
        BinaryOp::Power => "**",
        BinaryOp::Divide => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Ge => ">=",
        BinaryOp::Gt => ">",
        BinaryOp::Le => "<=",
        BinaryOp::Lt => "<",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::LogicAnd => "&&",
        BinaryOp::LogicOr => "||",
        BinaryOp::LogicXor => "^^",
    }
}

fn parse_number_text(text: &str, span: Span) -> Result<u32, AstEvalError> {
    let upper = text.to_ascii_uppercase();
    let cleaned = upper.replace('_', "");
    let (digits, base) = if let Some(rest) = cleaned.strip_prefix('$') {
        (rest.to_string(), 16)
    } else if let Some(rest) = cleaned.strip_prefix('%') {
        (rest.to_string(), 2)
    } else {
        match cleaned.chars().last() {
            Some('H') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 16),
            Some('B') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 2),
            Some('O') | Some('Q') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 8),
            Some('D') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 10),
            _ => (cleaned, 10),
        }
    };

    if digits.is_empty() {
        return Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Expression,
                "Illegal character in constant",
                Some(text),
            ),
            span,
        });
    }

    let valid = match base {
        2 => digits.chars().all(|c| c == '0' || c == '1'),
        8 => digits.chars().all(|c| matches!(c, '0'..='7')),
        10 => digits.chars().all(|c| c.is_ascii_digit()),
        16 => digits.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    };

    if !valid {
        let msg = match base {
            10 => "Illegal character in decimal constant",
            2 => "Illegal character in binary constant",
            8 => "Illegal character in octal constant",
            16 => "Illegal character in hex constant",
            _ => "Illegal character in constant",
        };
        return Err(AstEvalError {
            error: AsmError::new(AsmErrorKind::Expression, msg, Some(text)),
            span,
        });
    }

    let value = u32::from_str_radix(&digits, base).map_err(|_| AstEvalError {
        error: AsmError::new(
            AsmErrorKind::Expression,
            "Illegal character in constant",
            Some(text),
        ),
        span,
    })?;

    Ok(value)
}

fn format_error(msg: &str, param: Option<&str>) -> String {
    match param {
        Some(p) => format!("{msg}: {p}"),
        None => msg.to_string(),
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

            let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
                .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
            let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
                .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
            let ref_hex_path = reference_dir.join(format!("{base}.hex"));
            let ref_lst_path = reference_dir.join(format!("{base}.lst"));
            if update_reference {
                fs::write(&ref_hex_path, &out_hex).unwrap_or_else(|err| {
                    panic!("Failed to write reference hex {}: {err}", ref_hex_path.display())
                });
                fs::write(&ref_lst_path, &out_lst).unwrap_or_else(|err| {
                    panic!("Failed to write reference list {}: {err}", ref_lst_path.display())
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
    }

    #[test]
    fn org_sets_address() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .org 1000h", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.start_addr(), 0x1000);
        assert_eq!(asm.aux_value(), 0x1000);

        let status = process_line(&mut asm, "* = 1200h", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.start_addr(), 0x1200);
    }

    #[test]
    fn ds_reserves_space_and_defines_label() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "BUFFER: .ds 4", 0x0200, 1);
        assert_eq!(status, LineStatus::DirDs);
        assert_eq!(asm.aux_value(), 4);
        assert_eq!(asm.symbols().lookup("BUFFER"), 0x0200);
    }

    #[test]
    fn db_and_dw_emit_bytes() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .byte 1, 2, 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 2, 3]);

        let status = process_line(&mut asm, "    .word 7", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);
    }

    #[test]
    fn equ_defines_symbol_for_pass2() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "VAL .const 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), 3);

        let status = process_line(&mut asm, "    .word VAL+1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[4, 0]);
    }

    #[test]
    fn scoped_symbols_resolve_in_current_scope() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "SCOPE .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "    .word VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3, 0]);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.symbols().lookup("SCOPE.VAL"), 3);
        assert_eq!(asm.symbols().lookup("VAL"), NO_ENTRY);
    }

    #[test]
    fn qualified_symbol_resolves_outside_scope() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
    fn var_allows_redefinition_and_set_alias() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "VAL .var 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), 1);

        let status = process_line(&mut asm, "VAL .var 2", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), 2);

        let status = process_line(&mut asm, "VAL .set 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), 3);
    }

    #[test]
    fn assignment_ops_update_symbols() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);

        let status = process_line(&mut asm, "WIDTH = 40", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("WIDTH"), 40);

        let status = process_line(&mut asm, "var2 := 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), 1);

        let status = process_line(&mut asm, "var2 += 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), 2);

        let status = process_line(&mut asm, "var2 *= 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), 6);

        let status = process_line(&mut asm, "var2 <?= 4", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), 4);

        let status = process_line(&mut asm, "var2 >?= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), 5);

        let status = process_line(&mut asm, "var3 :?= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var3"), 5);

        let status = process_line(&mut asm, "var3 :?= 7", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var3"), 5);

        let status = process_line(&mut asm, "rep := $ab", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "rep x= 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("rep"), 0x00ababab);

        let status = process_line(&mut asm, "cat := $12", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "cat ..= $3456", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("cat"), 0x00123456);

        let status = process_line(&mut asm, "mem := 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "mem .= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("mem"), 5);
    }

    #[test]
    fn label_without_colon_defines_symbol() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "LABEL NOP", 0x1000, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.symbols().lookup("LABEL"), 0x1000);
    }

    #[test]
    fn set_without_dot_is_not_directive() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    SET 1", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    }

    #[test]
    fn undotted_directives_are_not_recognized() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    ORG 1000h", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
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
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .word MISSING", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.symbols().lookup("MISSING"), NO_ENTRY);
    }

    #[test]
    fn expression_precedence_and_ops() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(
            &mut asm,
            "    .word $1f, %1010, 1_0_0_0, 17o, 17q",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(
            asm.bytes(),
            &[0x1f, 0x00, 0x0a, 0x00, 0xe8, 0x03, 0x0f, 0x00, 0x0f, 0x00]
        );
    }

    #[test]
    fn expression_comparisons_and_logicals() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(
            &mut asm,
            "    .byte 3==3, 3!=4, 3<>4, 3<=3, 2<3, 3>=2, 3>2, 4=4",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1, 1, 1, 1, 1, 1, 1]);

        let status = process_line(
            &mut asm,
            "    .byte 2&&3, 0||5, 2^^3, !0, !1",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1, 0, 1, 0]);
    }

    #[test]
    fn expression_bitwise_ops() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .byte >($1234+1), <($1234+1)", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x12, 0x35]);
    }

    #[test]
    fn expression_not_equal_aliases() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .byte 3 <> 4, 3 != 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1]);
    }

    #[test]
    fn expression_nested_ternary_with_parens() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .word 1_2_3_4h, 0_f_f_fh", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x34, 0x12, 0xff, 0x0f]);
    }

    #[test]
    fn conditional_nesting_state_changes() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);

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
        let mut asm = AsmLine::new(&mut symbols);
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
    fn expression_high_low_and_unary() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
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
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .word $ + 1", 0x1000, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x10]);
    }

    #[test]
    fn conditional_errors_for_mismatched_blocks() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .else", 0, 2);
        assert_eq!(status, LineStatus::Error);

        let status = process_line(&mut asm, "    .endif", 0, 2);
        assert_eq!(status, LineStatus::Error);
    }

    #[test]
    fn column_one_errors_for_identifier() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "1mov a,b", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert!(asm.error_message().contains("column 1"));
    }

    #[test]
    fn error_kind_for_parser_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "123", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Parser);
    }

    #[test]
    fn error_kind_for_directive_failure() {
        let mut symbols = SymbolTable::new();
        let mut asm = AsmLine::new(&mut symbols);
        let status = process_line(&mut asm, "    .const 5", 0, 1);
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
        let status = process_line(&mut asm, "    .word 1/0", 0, 2);
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
