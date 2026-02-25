// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::text_utils::{is_ident_char, is_ident_start, to_upper, Cursor};

use super::{MacroArgs, MacroError, MacroParam};

pub(super) fn token_text_for_substitution(token: &crate::core::tokenizer::Token) -> String {
    token.to_source_text()
}

pub(super) fn parse_macro_params(text: &str, line_num: u32) -> Result<Vec<MacroParam>, MacroError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_params(text);
    let mut params = Vec::new();
    for part in parts {
        let spec = part.trim();
        if spec.is_empty() {
            return Err(MacroError::new(
                "Macro parameter cannot be empty",
                Some(line_num),
                None,
            ));
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
        let mut parts = name.split_whitespace().collect::<Vec<_>>();
        let (type_name, param_name) = match parts.len() {
            1 => (None, parts.remove(0)),
            2 => (Some(parts.remove(0)), parts.remove(0)),
            _ => {
                return Err(MacroError::new(
                    "Invalid macro parameter format",
                    Some(line_num),
                    None,
                ));
            }
        };
        if let Some(t) = type_name {
            if !is_valid_ident(t) {
                return Err(MacroError::new(
                    "Invalid macro parameter type",
                    Some(line_num),
                    None,
                ));
            }
        }
        if !is_valid_ident(param_name) {
            return Err(MacroError::new(
                "Invalid macro parameter name",
                Some(line_num),
                None,
            ));
        }
        params.push(MacroParam {
            name: Some(param_name.to_string()),
            default,
            type_name: type_name.map(|value| value.to_string()),
        });
    }
    Ok(params)
}

pub(super) fn parse_macro_args(text: &str, line_num: u32) -> Result<Vec<String>, MacroError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_params(text);
    let mut out = Vec::new();
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(MacroError::new(
                "Macro argument cannot be empty",
                Some(line_num),
                None,
            ));
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

fn split_params(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
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
            '(' if !in_single && !in_double => {
                paren_depth += 1;
            }
            ')' if !in_single && !in_double => {
                paren_depth = paren_depth.saturating_sub(1);
            }
            '[' if !in_single && !in_double => {
                bracket_depth += 1;
            }
            ']' if !in_single && !in_double => {
                bracket_depth = bracket_depth.saturating_sub(1);
            }
            '{' if !in_single && !in_double => {
                brace_depth += 1;
            }
            '}' if !in_single && !in_double => {
                brace_depth = brace_depth.saturating_sub(1);
            }
            ',' if !in_single
                && !in_double
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                out.push(current.clone());
                current.clear();
                i += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }
    out.push(current);
    out
}

pub(super) fn extract_paren_list(
    code: &str,
    start: usize,
    line_num: u32,
) -> Result<(String, usize), MacroError> {
    let bytes = code.as_bytes();
    if bytes.get(start) != Some(&b'(') {
        return Err(MacroError::new(
            "Expected '(' to start argument list",
            Some(line_num),
            Some(start + 1),
        ));
    }
    let mut i = start + 1;
    let mut depth = 1usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\\' if (in_single || in_double) && i + 1 < bytes.len() => {
                i += 2;
                continue;
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '(' if !in_single && !in_double => {
                depth += 1;
            }
            ')' if !in_single && !in_double => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let inner = code[start + 1..i].to_string();
                    return Ok((inner, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(MacroError::new(
        "Unterminated argument list",
        Some(line_num),
        Some(start + 1),
    ))
}

pub(super) fn substitute_line(line: &str, args: &MacroArgs) -> String {
    let mut out = String::new();
    // Substitution scanning is ASCII-oriented by contract; macro sigils and
    // identifier checks are byte-based and mirror tokenizer identifier rules.
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '.' => {
                if i + 1 >= bytes.len() {
                    out.push(c);
                    i += 1;
                    continue;
                }
                let next = bytes[i + 1] as char;
                match next {
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
                            if has_named(args, name) {
                                out.push_str(lookup_named(args, name));
                                i = j + 1;
                                continue;
                            }
                        }
                    }
                    _ => {
                        if is_ident_start(bytes[i + 1]) {
                            let mut j = i + 2;
                            while j < bytes.len() && is_ident_char(bytes[j]) {
                                j += 1;
                            }
                            let name = &line[i + 1..j];
                            if has_named(args, name) {
                                out.push_str(lookup_named(args, name));
                                i = j;
                                continue;
                            }
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

fn has_named(args: &MacroArgs, name: &str) -> bool {
    let key = to_upper(name);
    args.named.contains_key(&key)
}

pub(super) fn parse_label(line: &str) -> (Option<String>, usize, String) {
    let mut cursor = Cursor::new(line);
    cursor.skip_ws();
    let indent = line[..cursor.pos()].to_string();
    if cursor.peek().is_none() {
        return (None, cursor.pos(), indent);
    }
    let Some(first) = cursor.peek() else {
        return (None, cursor.pos(), indent);
    };
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

pub(super) fn is_valid_ident(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if is_ident_start(c as u8) => {}
        _ => return false,
    }
    chars.all(|c| is_ident_char(c as u8))
}
