// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::text_utils::{is_ident_start, is_space, to_upper, Cursor};
use std::collections::HashMap;

use super::{MacroArgs, MacroDef, MacroError, MacroInvocation, MacroKind};

use super::macro_processor_args_subst::{extract_paren_list, parse_label, parse_macro_args};

pub(super) fn parse_macro_def_line(
    code: &str,
    line_num: u32,
) -> Result<Option<(String, String, MacroKind)>, MacroError> {
    let (label, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return Ok(None);
    }
    cursor.next();
    cursor.skip_ws();
    let directive = match cursor.take_ident() {
        Some(name) => name.to_ascii_uppercase(),
        None => return Ok(None),
    };
    let kind = match directive.as_str() {
        "MACRO" => MacroKind::Macro,
        "SEGMENT" => MacroKind::Segment,
        _ => return Ok(None),
    };
    cursor.skip_ws();

    if let Some(name) = label {
        let params = code[cursor.pos()..].trim().to_string();
        return Ok(Some((name, params, kind)));
    }

    let name = cursor.take_ident().ok_or_else(|| {
        MacroError::new(
            "Macro name is required after directive",
            Some(line_num),
            Some(cursor.pos() + 1),
        )
    })?;
    cursor.skip_ws();

    let params = if cursor.peek() == Some(b'(') {
        let (inside, end_pos) = extract_paren_list(code, cursor.pos(), line_num)?;
        let rest = code[end_pos..].trim();
        if !rest.is_empty() {
            return Err(MacroError::new(
                "Unexpected tokens after macro parameter list",
                Some(line_num),
                Some(end_pos + 1),
            ));
        }
        inside
    } else {
        code[cursor.pos()..].trim().to_string()
    };

    Ok(Some((name, params, kind)))
}

pub(super) fn parse_macro_end_line(code: &str) -> Option<MacroKind> {
    let (_, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return None;
    }
    cursor.next();
    cursor.skip_ws();
    let directive = cursor.take_ident().unwrap_or_default().to_ascii_uppercase();
    match directive.as_str() {
        "ENDMACRO" | "ENDM" => Some(MacroKind::Macro),
        "ENDSEGMENT" | "ENDS" => Some(MacroKind::Segment),
        _ => None,
    }
}

pub(super) fn parse_macro_invocation(
    code: &str,
    macros: &HashMap<String, MacroDef>,
    namespace_stack: &[Option<String>],
    line_num: u32,
) -> Result<Option<MacroInvocation>, MacroError> {
    let (label, idx, indent) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek().is_none() {
        return Ok(None);
    }
    match cursor.peek() {
        Some(b'.') => {
            cursor.next();
        }
        _ => return Ok(None),
    }
    let Some(next) = cursor.peek() else {
        return Ok(None);
    };
    if !is_ident_start(next) {
        return Ok(None);
    }
    let Some(name) = cursor.take_ident() else {
        return Ok(None);
    };
    let Some(resolved_key) = resolve_macro_lookup_key(&name, namespace_stack, macros) else {
        return Ok(None);
    };

    let mut pos = cursor.pos();
    while code.as_bytes().get(pos).is_some_and(|c| is_space(*c)) {
        pos += 1;
    }

    let (full_list, end_pos) = if code.as_bytes().get(pos) == Some(&b'(') {
        let (inside, end_pos) = extract_paren_list(code, pos, line_num)?;
        (inside, end_pos)
    } else {
        let mut rest = code[pos..].trim_start().to_string();
        if rest.starts_with(',') {
            rest = rest[1..].trim_start().to_string();
            if rest.is_empty() {
                return Err(MacroError::new(
                    "Empty macro argument list",
                    Some(line_num),
                    Some(pos + 1),
                ));
            }
        }
        (rest, code.len())
    };

    if end_pos < code.len() && !code[end_pos..].trim().is_empty() {
        return Err(MacroError::new(
            "Unexpected tokens after macro argument list",
            Some(line_num),
            Some(end_pos + 1),
        ));
    }

    let args = parse_macro_args(&full_list, line_num)?;
    Ok(Some(MacroInvocation {
        label,
        resolved_key,
        args,
        full_list,
        indent,
    }))
}

fn resolve_macro_lookup_key(
    name: &str,
    namespace_stack: &[Option<String>],
    macros: &HashMap<String, MacroDef>,
) -> Option<String> {
    let exact = to_upper(name);
    if macros.contains_key(&exact) {
        return Some(exact);
    }
    if name.contains('.') {
        return None;
    }
    let namespace_parts: Vec<&str> = namespace_stack
        .iter()
        .filter_map(|part| part.as_deref())
        .collect();
    if namespace_parts.is_empty() {
        return None;
    }
    for depth in (1..=namespace_parts.len()).rev() {
        let mut qualified = namespace_parts[..depth].join(".");
        qualified.push('.');
        qualified.push_str(&exact);
        if macros.contains_key(&qualified) {
            return Some(qualified);
        }
    }
    None
}

pub(super) fn build_macro_args(def: &MacroDef, inv: &MacroInvocation) -> MacroArgs {
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

pub(super) fn format_macro_block_start(inv: &MacroInvocation) -> String {
    if let Some(label) = &inv.label {
        format!("{} .block", label)
    } else {
        format!("{}{}", inv.indent, ".block")
    }
}
