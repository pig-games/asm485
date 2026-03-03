// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLookupContext {
    pub base_symbol: String,
    pub field_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCompletionContext {
    pub base_symbol: String,
    pub field_prefix: String,
}

pub fn member_lookup_context(line: &str, character: usize) -> Option<MemberLookupContext> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let cursor = character.min(bytes.len());
    let mut field_start = cursor;
    while field_start > 0 && is_member_field_char(bytes[field_start - 1]) {
        field_start -= 1;
    }
    let mut field_end = cursor;
    while field_end < bytes.len() && is_member_field_char(bytes[field_end]) {
        field_end += 1;
    }
    if field_start == field_end {
        return None;
    }
    let field_name = line[field_start..field_end].to_string();
    if field_name.is_empty() {
        return None;
    }
    let mut dot_idx = field_start;
    while dot_idx > 0 && bytes[dot_idx - 1].is_ascii_whitespace() {
        dot_idx -= 1;
    }
    if dot_idx == 0 || bytes[dot_idx - 1] != b'.' {
        return None;
    }
    let base_symbol = parse_base_before_dot(line, dot_idx - 1)?;
    Some(MemberLookupContext {
        base_symbol,
        field_name,
    })
}

pub fn member_completion_context(line: &str, character: usize) -> Option<MemberCompletionContext> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let cursor = character.min(bytes.len());
    let mut field_start = cursor;
    while field_start > 0 && is_member_field_char(bytes[field_start - 1]) {
        field_start -= 1;
    }
    let field_prefix = line[field_start..cursor].to_string();
    let mut dot_idx = field_start;
    while dot_idx > 0 && bytes[dot_idx - 1].is_ascii_whitespace() {
        dot_idx -= 1;
    }
    if dot_idx == 0 || bytes[dot_idx - 1] != b'.' {
        return None;
    }
    let base_symbol = parse_base_before_dot(line, dot_idx - 1)?;
    Some(MemberCompletionContext {
        base_symbol,
        field_prefix,
    })
}

fn parse_base_before_dot(line: &str, dot_pos: usize) -> Option<String> {
    let bytes = line.as_bytes();
    let mut end = dot_pos;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }

    // Allow indexed member chains like points[1].x by walking bracket groups backward.
    loop {
        let mut scan = end;
        while scan > 0 && bytes[scan - 1].is_ascii_whitespace() {
            scan -= 1;
        }
        if scan == 0 || bytes[scan - 1] != b']' {
            end = scan;
            break;
        }

        let mut depth = 1usize;
        let mut idx = scan - 1;
        while idx > 0 {
            idx -= 1;
            match bytes[idx] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        if depth != 0 {
            return None;
        }
        end = idx;
    }

    let mut start = end;
    while start > 0 && is_base_symbol_char(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    let base = line[start..end].trim();
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

fn is_member_field_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn is_base_symbol_char(byte: u8) -> bool {
    is_member_field_char(byte) || byte == b'.'
}

#[cfg(test)]
mod tests {
    use super::{member_completion_context, member_lookup_context};

    #[test]
    fn lookup_context_resolves_simple_member_access() {
        let line = "    lda p0.color";
        let ctx = member_lookup_context(line, line.len()).expect("lookup context");
        assert_eq!(ctx.base_symbol, "p0");
        assert_eq!(ctx.field_name, "color");
    }

    #[test]
    fn lookup_context_resolves_indexed_member_access() {
        let line = "    lda points[1].x";
        let field_col = line.find(".x").expect("dot member") + 2;
        let ctx = member_lookup_context(line, field_col).expect("lookup context");
        assert_eq!(ctx.base_symbol, "points");
        assert_eq!(ctx.field_name, "x");
    }

    #[test]
    fn completion_context_resolves_dot_without_field_name() {
        let line = "    lda points[2].";
        let ctx = member_completion_context(line, line.len()).expect("completion context");
        assert_eq!(ctx.base_symbol, "points");
        assert_eq!(ctx.field_prefix, "");
    }
}
