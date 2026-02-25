// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::text_utils::Cursor;

use super::macro_processor_args_subst::parse_label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatementDirective {
    Def,
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VisibilityDirective {
    SetPublic,
    SetPrivate,
    PushScope,
    PopScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NamespaceDirective {
    Push(Option<String>),
    Pop,
}

pub(super) fn parse_visibility_directive(code: &str) -> Option<VisibilityDirective> {
    let (_, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return None;
    }
    cursor.next();
    cursor.skip_ws();
    let directive = cursor.take_ident()?.to_ascii_uppercase();
    match directive.as_str() {
        "PUB" => Some(VisibilityDirective::SetPublic),
        "PRIV" => Some(VisibilityDirective::SetPrivate),
        "BLOCK" | "MODULE" | "NAMESPACE" => Some(VisibilityDirective::PushScope),
        "ENDBLOCK" | "BEND" | "ENDMODULE" | "ENDN" | "ENDNAMESPACE" => {
            Some(VisibilityDirective::PopScope)
        }
        _ => None,
    }
}

pub(super) fn parse_namespace_directive(code: &str) -> Option<NamespaceDirective> {
    let (label, idx, _) = parse_label(code);
    let mut cursor = Cursor::with_pos(code, idx);
    cursor.skip_ws();
    if cursor.peek() != Some(b'.') {
        return None;
    }
    cursor.next();
    cursor.skip_ws();
    let directive = cursor.take_ident()?.to_ascii_uppercase();
    match directive.as_str() {
        "NAMESPACE" => {
            cursor.skip_ws();
            let name = if let Some(name) = cursor.take_ident() {
                Some(name)
            } else {
                label
            };
            Some(NamespaceDirective::Push(name))
        }
        "ENDN" | "ENDNAMESPACE" => Some(NamespaceDirective::Pop),
        _ => None,
    }
}

pub(super) fn parse_statement_directive(code: &str) -> Option<StatementDirective> {
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
        "STATEMENT" => Some(StatementDirective::Def),
        "ENDSTATEMENT" => Some(StatementDirective::End),
        _ => None,
    }
}
