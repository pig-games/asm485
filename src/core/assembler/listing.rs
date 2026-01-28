// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Listing file generation.

use std::io::Write;

use crate::core::parser::ParseError;
use crate::core::parser_reporter::format_parse_error_listing;
use crate::core::symbol_table::SymbolTable;

use super::conditional::ConditionalContext;
use super::error::{build_context_lines, LineStatus, PassCounts};

/// Data for a single listing line.
pub struct ListingLine<'a> {
    pub addr: u16,
    pub bytes: &'a [u8],
    pub status: LineStatus,
    pub aux: u16,
    pub line_num: u32,
    pub source: &'a str,
    pub cond: Option<&'a ConditionalContext>,
}

/// Writer for listing file output.
pub struct ListingWriter<W: Write> {
    out: W,
    show_cond: bool,
}

impl<W: Write> ListingWriter<W> {
    pub fn new(out: W, show_cond: bool) -> Self {
        Self { out, show_cond }
    }

    pub fn header(&mut self, title: &str) -> std::io::Result<()> {
        writeln!(self.out, "{title}")?;
        writeln!(self.out, "ADDR    BYTES                    LINE  SOURCE")?;
        writeln!(self.out, "------  -----------------------  ----  ------")?;
        Ok(())
    }

    pub fn write_line(&mut self, line: ListingLine<'_>) -> std::io::Result<()> {
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

    pub fn write_diagnostic(
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

    pub fn footer(
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

/// Format bytes as hex string for listing.
pub fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format conditional context for debug display.
fn format_cond(ctx: &ConditionalContext) -> String {
    let matched = if ctx.matched { '+' } else { ' ' };
    let skipping = if ctx.skipping { '-' } else { ' ' };
    format!("  [{}{}{}{}]", matched, ctx.nest_level, ctx.skip_level, skipping)
}
