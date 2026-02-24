// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Listing file generation.

use std::collections::BTreeMap;
use std::io::Write;

use crate::core::symbol_table::SymbolTable;
use crate::core::text_utils::{is_ident_start, split_comment, Cursor};

use super::conditional::ConditionalContext;
use super::error::{build_context_lines, LineStatus, PassCounts};

/// Data for a single listing line.
pub struct ListingLine<'a> {
    pub addr: u32,
    pub bytes: &'a [u8],
    pub status: LineStatus,
    pub aux: u32,
    pub line_num: u32,
    pub source: &'a str,
    pub section: Option<&'a str>,
    pub cond: Option<&'a ConditionalContext>,
}

/// Writer for listing file output.
pub struct ListingWriter<W: Write> {
    out: W,
    show_cond: bool,
    tab_size: Option<usize>,
}

impl<W: Write> ListingWriter<W> {
    pub fn new(out: W, show_cond: bool) -> Self {
        Self {
            out,
            show_cond,
            tab_size: None,
        }
    }

    pub fn new_with_options(out: W, show_cond: bool, tab_size: Option<usize>) -> Self {
        Self {
            out,
            show_cond,
            tab_size,
        }
    }

    pub fn header(&mut self, title: &str) -> std::io::Result<()> {
        writeln!(self.out, "{title}")?;
        writeln!(self.out, "ADDR    BYTES                    LINE  SOURCE")?;
        writeln!(self.out, "------  -----------------------  ----  ------")?;
        Ok(())
    }

    pub fn write_line(&mut self, line: ListingLine<'_>) -> std::io::Result<()> {
        let (loc, bytes_col) = match line.status {
            LineStatus::DirEqu => (String::new(), format!("EQU {}", format_addr(line.aux))),
            LineStatus::DirDs => (
                format_addr(line.addr),
                format!("+{}", format_addr(line.aux)),
            ),
            _ => {
                if line.bytes.is_empty() {
                    ("".to_string(), String::new())
                } else {
                    (format_addr(line.addr), format_bytes(line.bytes))
                }
            }
        };

        let loc = if loc.is_empty() {
            "----".to_string()
        } else {
            loc
        };
        let section_suffix = line
            .section
            .map(|name| format!("  ; [section {name}]"))
            .unwrap_or_default();
        let cond_str = if self.show_cond {
            line.cond.map(format_cond).unwrap_or_default()
        } else {
            String::new()
        };
        let normalized_source = normalize_leading_label_colon(line.source);
        let normalized_source = strip_ansi_sgr(&normalized_source);
        let source = if let Some(tab_size) = self.tab_size {
            expand_tabs(&normalized_source, tab_size)
        } else {
            normalized_source
        };

        writeln!(
            self.out,
            "{:<6}  {:<23}  {:>4}  {}{}",
            loc,
            bytes_col,
            line.line_num,
            source,
            format_args!("{section_suffix}{cond_str}")
        )
    }

    pub fn write_diagnostic(
        &mut self,
        kind: &str,
        msg: &str,
        line_num: u32,
        column: Option<usize>,
        source_lines: &[String],
        _parser_error: Option<&crate::core::parser::ParseError>,
    ) -> std::io::Result<()> {
        let context = build_context_lines(line_num, column, Some(source_lines), None, false);
        for line in context {
            writeln!(self.out, "{}", strip_ansi_sgr(&line))?;
        }
        writeln!(self.out, "{kind}: {msg}")
    }

    pub fn footer(
        &mut self,
        counts: &PassCounts,
        symbols: &SymbolTable,
        total_mem: usize,
    ) -> std::io::Result<()> {
        self.footer_with_generated_output(counts, symbols, total_mem, &[])
    }

    pub fn footer_with_generated_output(
        &mut self,
        counts: &PassCounts,
        symbols: &SymbolTable,
        total_mem: usize,
        generated_output: &[(u32, u8)],
    ) -> std::io::Result<()> {
        writeln!(
            self.out,
            "\nLines: {}  Errors: {}  Warnings: {}",
            counts.lines, counts.errors, counts.warnings
        )?;
        writeln!(self.out, "\nSYMBOL TABLE\n")?;
        symbols.dump(&mut self.out)?;
        writeln!(self.out, "\nTotal memory is {} bytes", total_mem)?;
        self.write_generated_output(generated_output)?;
        Ok(())
    }

    fn write_generated_output(&mut self, generated_output: &[(u32, u8)]) -> std::io::Result<()> {
        writeln!(self.out, "\nGENERATED OUTPUT\n")?;
        if generated_output.is_empty() {
            writeln!(self.out, "(none)")?;
            return Ok(());
        }

        let mut resolved = BTreeMap::new();
        for (addr, value) in generated_output {
            resolved.insert(*addr, *value);
        }

        writeln!(self.out, "ADDR    BYTES")?;
        writeln!(self.out, "------  -----------------------")?;

        let mut line_addr: Option<u32> = None;
        let mut prev_addr: Option<u32> = None;
        let mut line_bytes: Vec<u8> = Vec::new();

        for (addr, value) in resolved {
            let split = match prev_addr {
                Some(prev) => addr != prev.wrapping_add(1) || line_bytes.len() >= 16,
                None => false,
            };
            if split {
                if let Some(start) = line_addr {
                    writeln!(
                        self.out,
                        "{}    {}",
                        format_addr(start),
                        format_bytes(&line_bytes)
                    )?;
                }
                line_bytes.clear();
                line_addr = Some(addr);
            }
            if line_addr.is_none() {
                line_addr = Some(addr);
            }
            line_bytes.push(value);
            prev_addr = Some(addr);
        }

        if let Some(start) = line_addr {
            writeln!(
                self.out,
                "{}    {}",
                format_addr(start),
                format_bytes(&line_bytes)
            )?;
        }

        Ok(())
    }
}

fn normalize_leading_label_colon(source: &str) -> String {
    let (code, comment) = split_comment(source);
    let mut cursor = Cursor::new(code);
    cursor.skip_ws();
    let indent_end = cursor.pos();
    let Some(first) = cursor.peek() else {
        return source.to_string();
    };
    if matches!(first, b'.' | b'*' | b';' | b'#') {
        return source.to_string();
    }
    if !is_ident_start(first) {
        return source.to_string();
    }
    let Some(label) = cursor.take_ident() else {
        return source.to_string();
    };
    if cursor.peek() != Some(b':') {
        return source.to_string();
    }
    cursor.next();

    let remainder = &code[cursor.pos()..];
    let mut normalized = String::with_capacity(source.len() + 1);
    normalized.push_str(&code[..indent_end]);
    normalized.push_str(&label);
    if !remainder.is_empty() {
        let needs_space = !remainder.starts_with(' ') && !remainder.starts_with('\t');
        if needs_space {
            normalized.push(' ');
        }
        normalized.push_str(remainder);
    }
    normalized.push_str(comment);
    normalized
}

fn format_addr(addr: u32) -> String {
    if addr <= 0xFFFF {
        format!("{addr:04X}")
    } else if addr <= 0xFF_FFFF {
        format!("{addr:06X}")
    } else {
        format!("{addr:08X}")
    }
}

fn expand_tabs(source: &str, tab_size: usize) -> String {
    if tab_size == 0 {
        return source.to_string();
    }
    let mut expanded = String::new();
    let mut column = 0usize;
    for ch in source.chars() {
        if ch == '\t' {
            let spaces = tab_size - (column % tab_size);
            expanded.push_str(&" ".repeat(spaces));
            column += spaces;
        } else {
            expanded.push(ch);
            column += 1;
        }
    }
    expanded
}

fn strip_ansi_sgr(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }

    out
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
    format!(
        "  [{}{}{}{}]",
        matched, ctx.nest_level, ctx.skip_level, skipping
    )
}

#[cfg(test)]
mod tests {
    use super::{ListingLine, ListingWriter};
    use crate::core::assembler::error::LineStatus;

    #[test]
    fn dir_equ_listing_keeps_wide_value() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::DirEqu,
                aux: 0x123456,
                line_num: 1,
                source: "value = $123456",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("EQU 123456"));
    }

    #[test]
    fn dir_ds_listing_keeps_wide_reserve_size() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0x010000,
                bytes: &[],
                status: LineStatus::DirDs,
                aux: 0x123456,
                line_num: 2,
                source: ".res byte, $123456",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("010000"));
        assert!(text.contains("+123456"));
    }

    #[test]
    fn listing_tab_size_expands_tabs_when_configured() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new_with_options(&mut out, false, Some(4));
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::Ok,
                aux: 0,
                line_num: 1,
                source: "\tlda\t#1",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("    lda #1"));
    }

    #[test]
    fn listing_normalizes_leading_label_colon() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::Ok,
                aux: 0,
                line_num: 1,
                source: "label: nop",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("label nop"));
        assert!(!text.contains("label: nop"));
    }

    #[test]
    fn listing_normalizes_tight_label_colon() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::Ok,
                aux: 0,
                line_num: 1,
                source: "label:nop",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("label nop"));
        assert!(!text.contains("label:nop"));
    }

    #[test]
    fn listing_diagnostic_output_does_not_include_ansi_sequences() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        let source_lines =
            vec![".statement move.b char:dst\u{1b}[31m,\u{1b}[0m char:src".to_string()];
        writer
            .write_diagnostic(
                "ERROR",
                "Commas must be quoted in statement signatures",
                1,
                Some(27),
                &source_lines,
                None,
            )
            .expect("write diagnostic");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("\u{1b}[31m"));
        assert!(!text.contains("\u{1b}[0m"));
        assert!(text.contains("ERROR: Commas must be quoted in statement signatures"));
    }

    #[test]
    fn listing_source_line_strips_ansi_sequences() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::Ok,
                aux: 0,
                line_num: 1,
                source: "label:\u{1b}[31mnop\u{1b}[0m",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("\u{1b}[31m"));
        assert!(!text.contains("\u{1b}[0m"));
        assert!(text.contains("label nop"));
    }

    #[test]
    fn listing_source_line_keeps_utf8_characters_while_stripping_ansi() {
        let mut out = Vec::new();
        let mut writer = ListingWriter::new(&mut out, false);
        writer
            .write_line(ListingLine {
                addr: 0,
                bytes: &[],
                status: LineStatus::Ok,
                aux: 0,
                line_num: 1,
                source: "; LD — INDEX\u{1b}[31m REGISTER\u{1b}[0m",
                section: None,
                cond: None,
            })
            .expect("write listing line");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("LD — INDEX REGISTER"));
        assert!(!text.contains("\u{1b}[31m"));
        assert!(!text.contains("\u{1b}[0m"));
    }
}
