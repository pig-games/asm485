// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Assembler macro processor implementing 64tass-style .macro/.endmacro expansion.

use crate::core::text_utils::{is_ident_char, is_ident_start, is_space, to_upper};
use std::collections::HashMap;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn with_pos(input: &'a str, pos: usize) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn take_ident(&mut self) -> Option<String> {
        let start = self.pos;
        let first = self.peek()?;
        if !is_ident_start(first) {
            return None;
        }
        self.pos += 1;
        while self.peek().is_some_and(is_ident_char) {
            self.pos += 1;
        }
        Some(String::from_utf8_lossy(&self.bytes[start..self.pos]).to_string())
    }
}

#[derive(Debug, Clone)]
pub struct MacroError {
    message: String,
    line: Option<u32>,
    column: Option<usize>,
}

impl MacroError {
    fn new(message: impl Into<String>, line: Option<u32>, column: Option<usize>) -> Self {
        Self {
            message: message.into(),
            line,
            column,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn line(&self) -> Option<u32> {
        self.line
    }

    pub fn column(&self) -> Option<usize> {
        self.column
    }
}

#[derive(Debug, Clone)]
struct MacroParam {
    name: Option<String>,
    default: Option<String>,
}

#[derive(Debug, Clone)]
struct MacroDef {
    params: Vec<MacroParam>,
    body: Vec<String>,
    wrap_scope: bool,
}

#[derive(Debug, Clone)]
struct MacroInvocation {
    label: Option<String>,
    name: String,
    args: Vec<String>,
    full_list: String,
    indent: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacroKind {
    Macro,
    Segment,
}

#[derive(Debug, Clone)]
struct MacroArgs {
    positional: Vec<String>,
    named: HashMap<String, String>,
    full_list: String,
}

pub struct MacroProcessor {
    macros: HashMap<String, MacroDef>,
    max_depth: usize,
}

impl Default for MacroProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl MacroProcessor {
    pub fn new() -> Self {
        Self {
            macros: HashMap::new(),
            max_depth: 64,
        }
    }

    pub fn expand(&mut self, lines: &[String]) -> Result<Vec<String>, MacroError> {
        self.expand_lines(lines, 0)
    }

    fn expand_lines(&mut self, lines: &[String], depth: usize) -> Result<Vec<String>, MacroError> {
        if depth > self.max_depth {
            return Err(MacroError::new(
                "Macro expansion exceeded maximum depth",
                None,
                None,
            ));
        }

        let mut out = Vec::new();
        let mut current: Option<(String, MacroDef, MacroKind)> = None;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx as u32 + 1;
            let (code, _) = split_comment(line);

            if let Some((name, params, kind)) = parse_macro_def_line(&code) {
                if current.is_some() {
                    return Err(MacroError::new(
                        "Nested .macro definitions are not supported",
                        Some(line_num),
                        Some(1),
                    ));
                }
                if name.is_empty() {
                    return Err(MacroError::new(
                        "Macro name is required before .macro",
                        Some(line_num),
                        Some(1),
                    ));
                }
                if self.macros.contains_key(&to_upper(&name)) {
                    return Err(MacroError::new(
                        "Macro already defined",
                        Some(line_num),
                        Some(1),
                    ));
                }
                let param_defs = parse_macro_params(&params, line_num)?;
                let wrap_scope = kind == MacroKind::Macro;
                current = Some((
                    name,
                    MacroDef {
                        params: param_defs,
                        body: Vec::new(),
                        wrap_scope,
                    },
                    kind,
                ));
                continue;
            }

            if let Some(kind) = parse_macro_end_line(&code) {
                let Some((name, def, active_kind)) = current.take() else {
                    let message = match kind {
                        MacroKind::Macro => ".endmacro found without matching .macro",
                        MacroKind::Segment => ".endsegment found without matching .segment",
                    };
                    return Err(MacroError::new(message, Some(line_num), Some(1)));
                };
                if kind != active_kind {
                    let message = match kind {
                        MacroKind::Macro => "Expected .endsegment for .segment",
                        MacroKind::Segment => "Expected .endmacro for .macro",
                    };
                    return Err(MacroError::new(message, Some(line_num), Some(1)));
                }
                self.macros.insert(to_upper(&name), def);
                continue;
            }

            if let Some((name, def, _kind)) = current.as_mut() {
                let _ = name;
                def.body.push(line.clone());
                continue;
            }

            if let Some(inv) = parse_macro_invocation(&code, &self.macros) {
                let def = self
                    .macros
                    .get(&to_upper(&inv.name))
                    .cloned()
                    .ok_or_else(|| {
                        MacroError::new("Unknown macro", Some(line_num), Some(1))
                    })?;
                let args = build_macro_args(&def, &inv);
                let mut expanded = Vec::new();
                if def.wrap_scope {
                    expanded.push(format_macro_block_start(&inv));
                }
                for body_line in &def.body {
                    expanded.push(substitute_line(body_line, &args));
                }
                if def.wrap_scope {
                    expanded.push(format!("{}{}", inv.indent, ".endblock"));
                } else if let Some(label) = &inv.label {
                    if let Some(first) = expanded.first_mut() {
                        let trimmed = first.trim_start();
                        if trimmed.is_empty() {
                            *first = label.clone();
                        } else {
                            *first = format!("{label} {trimmed}");
                        }
                    } else {
                        expanded.push(label.clone());
                    }
                }
                let nested = self.expand_lines(&expanded, depth + 1)?;
                out.extend(nested);
                continue;
            }

            out.push(line.clone());
        }

        if let Some((_name, _def, kind)) = current {
            let message = match kind {
                MacroKind::Macro => "Missing .endmacro for macro definition",
                MacroKind::Segment => "Missing .endsegment for segment definition",
            };
            return Err(MacroError::new(message, None, None));
        }

        Ok(out)
    }
}

fn parse_macro_def_line(code: &str) -> Option<(String, String, MacroKind)> {
    let (label, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return None;
    }
    cursor.next();
    cursor.skip_ws();
    let directive = cursor.take_ident()?.to_ascii_uppercase();
    let kind = match directive.as_str() {
        "MACRO" => MacroKind::Macro,
        "SEGMENT" => MacroKind::Segment,
        _ => return None,
    };
    let params = code[cursor.pos()..].trim().to_string();
    Some((label.unwrap_or_default(), params, kind))
}

fn parse_macro_end_line(code: &str) -> Option<MacroKind> {
    let (_, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return None;
    }
    cursor.next();
    cursor.skip_ws();
    let directive = cursor
        .take_ident()
        .unwrap_or_default()
        .to_ascii_uppercase();
    match directive.as_str() {
        "ENDMACRO" | "ENDM" => Some(MacroKind::Macro),
        "ENDSEGMENT" | "ENDS" => Some(MacroKind::Segment),
        _ => None,
    }
}

fn parse_macro_invocation(code: &str, macros: &HashMap<String, MacroDef>) -> Option<MacroInvocation> {
    let (label, idx, indent) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    cursor.peek()?;
    match cursor.peek() {
        Some(b'#') | Some(b'.') => {
            cursor.next();
        }
        _ => return None,
    }
    if cursor.peek().is_none() || !is_ident_start(cursor.peek().unwrap()) {
        return None;
    }
    let name = cursor.take_ident()?;
    if !macros.contains_key(&to_upper(&name)) {
        // If macro doesn't exist, return None to let the line pass through.
        // This allows 6502 immediate syntax like `lda #VALUE` to work
        // when VALUE is not a macro name.
        return None;
    }

    let mut rest = code[cursor.pos()..].to_string();
    if rest.starts_with(',') {
        rest = rest[1..].to_string();
    }
    let full_list = rest.trim_start().to_string();
    let args = parse_macro_args(&full_list);
    Some(MacroInvocation {
        label,
        name,
        args,
        full_list,
        indent,
    })
}

fn build_macro_args(def: &MacroDef, inv: &MacroInvocation) -> MacroArgs {
    let mut positional = Vec::new();
    let mut named = HashMap::new();

    let mut max_len = def.params.len().max(inv.args.len());
    if max_len < 9 {
        max_len = 9;
    }

    for idx in 0..max_len {
        let arg = inv.args.get(idx).cloned().unwrap_or_default();
        let mut value = arg;
        if idx < def.params.len() && value.trim().is_empty() {
            if let Some(default) = &def.params[idx].default {
                value = default.clone();
            }
        }
        positional.push(value.clone());
        if idx < def.params.len() {
            if let Some(name) = &def.params[idx].name {
                named.insert(to_upper(name), value);
            }
        }
    }

    MacroArgs {
        positional,
        named,
        full_list: inv.full_list.clone(),
    }
}

fn format_macro_block_start(inv: &MacroInvocation) -> String {
    if let Some(label) = &inv.label {
        format!("{} .block", label)
    } else {
        format!("{}{}", inv.indent, ".block")
    }
}

fn parse_macro_params(text: &str, line_num: u32) -> Result<Vec<MacroParam>, MacroError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_params(text);
    let mut params = Vec::new();
    for part in parts {
        let spec = part.trim();
        if spec.is_empty() {
            params.push(MacroParam { name: None, default: None });
            continue;
        }
        let (name, default) = if let Some((left, right)) = spec.split_once('=') {
            (left.trim(), Some(right.trim().to_string()))
        } else {
            (spec, None)
        };
        if name.is_empty() {
            return Err(MacroError::new(
                "Macro parameter name cannot be empty",
                Some(line_num),
                None,
            ));
        }
        if !is_valid_ident(name) {
            return Err(MacroError::new(
                "Invalid macro parameter name",
                Some(line_num),
                None,
            ));
        }
        params.push(MacroParam {
            name: Some(name.to_string()),
            default,
        });
    }
    Ok(params)
}

fn parse_macro_args(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let parts = split_params(text);
    parts.into_iter().map(|s| s.trim().to_string()).collect()
}

fn split_params(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut saw_sep = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\\' if (in_single || in_double) && i + 1 < bytes.len() => {
                current.push(c);
                i += 1;
                current.push(bytes[i] as char);
                i += 1;
                continue;
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ',' if !in_single && !in_double => {
                out.push(current.clone());
                current.clear();
                saw_sep = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }
    if !current.is_empty() || saw_sep {
        out.push(current);
    }
    out
}

fn substitute_line(line: &str, args: &MacroArgs) -> String {
    let mut out = String::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\\' => {
                if i + 1 >= bytes.len() {
                    out.push(c);
                    i += 1;
                    continue;
                }
                let next = bytes[i + 1] as char;
                match next {
                    '\\' => {
                        out.push('\\');
                        i += 2;
                        continue;
                    }
                    '@' => {
                        out.push_str(&args.full_list);
                        i += 2;
                        continue;
                    }
                    '1'..='9' => {
                        let idx = (next as u8 - b'1') as usize;
                        out.push_str(args.positional.get(idx).map(String::as_str).unwrap_or(""));
                        i += 2;
                        continue;
                    }
                    '{' => {
                        let mut j = i + 2;
                        while j < bytes.len() && bytes[j] != b'}' {
                            j += 1;
                        }
                        if j < bytes.len() {
                            let name = &line[i + 2..j];
                            out.push_str(lookup_named(args, name));
                            i = j + 1;
                            continue;
                        }
                    }
                    _ => {
                        if is_ident_start(bytes[i + 1]) {
                            let mut j = i + 2;
                            while j < bytes.len() && is_ident_char(bytes[j]) {
                                j += 1;
                            }
                            let name = &line[i + 1..j];
                            out.push_str(lookup_named(args, name));
                            i = j;
                            continue;
                        }
                    }
                }
            }
            '@' if i + 1 < bytes.len() => {
                let next = bytes[i + 1] as char;
                if next.is_ascii_digit() && next != '0' {
                    let idx = (next as u8 - b'1') as usize;
                    out.push_str(args.positional.get(idx).map(String::as_str).unwrap_or(""));
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        out.push(c);
        i += 1;
    }
    out
}

fn lookup_named<'a>(args: &'a MacroArgs, name: &str) -> &'a str {
    let key = to_upper(name);
    args.named.get(&key).map(String::as_str).unwrap_or("")
}

fn split_comment(line: &str) -> (String, String) {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, c) in line.char_indices() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ';' if !in_single && !in_double => {
                return (line[..idx].to_string(), line[idx..].to_string());
            }
            _ => {}
        }
    }
    (line.to_string(), String::new())
}

fn parse_label(line: &str) -> (Option<String>, usize, String) {
    let mut cursor = Cursor::new(line);
    cursor.skip_ws();
    let indent = line[..cursor.pos()].to_string();
    if cursor.peek().is_none() {
        return (None, cursor.pos(), indent);
    }
    let first = cursor.peek().unwrap();
    match first {
        b'.' | b'*' | b';' | b'#' => return (None, cursor.pos(), indent),
        _ => {}
    }
    if !is_ident_start(first) {
        return (None, cursor.pos(), indent);
    }
    let name = cursor.take_ident().unwrap_or_default();
    if cursor.peek() == Some(b':') {
        cursor.next();
    }
    (Some(name), cursor.pos(), indent)
}

fn is_valid_ident(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if is_ident_start(c as u8) => {}
        _ => return false,
    }
    chars.all(|c| is_ident_char(c as u8))
}

#[cfg(test)]
mod tests {
    use super::MacroProcessor;

    #[test]
    fn expands_simple_macro_with_params() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "COPY .macro src, dst".to_string(),
            "    lda \\src".to_string(),
            "    sta \\dst".to_string(),
            ".endmacro".to_string(),
            "    #COPY $12, $34".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.contains(&"    lda $12".to_string()));
        assert!(out.contains(&"    sta $34".to_string()));
        assert!(out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_named_and_default_params() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "M .macro first, second=2".to_string(),
            "    .byte \\first, \\second".to_string(),
            ".endmacro".to_string(),
            "    #M 1".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 1, 2".to_string()));
    }

    #[test]
    fn expands_text_and_list_refs() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "MSG .macro text".to_string(),
            "    .byte @1".to_string(),
            "    .word \\@".to_string(),
            ".endmacro".to_string(),
            "    .MSG 1+2".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 1+2".to_string()));
        assert!(out.contains(&"    .word 1+2".to_string()));
    }

    #[test]
    fn expands_segment_without_scope_block() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "INLINE .segment val".to_string(),
            "    .byte \\val".to_string(),
            ".endsegment".to_string(),
            "    .INLINE 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 7".to_string()));
        assert!(!out.iter().any(|line| line.trim() == ".block"));
        assert!(!out.iter().any(|line| line.trim() == ".endblock"));
    }
}
