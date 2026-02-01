// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Assembler macro processor implementing 64tass-style .macro/.endmacro expansion.

use crate::core::parser::{
    match_statement_signature,
    select_statement_signature,
    LineAst,
    Parser,
    StatementSignature,
};
use crate::core::tokenizer::{Span, Token, TokenKind, Tokenizer};
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
    #[allow(dead_code)]
    type_name: Option<String>,
}

#[derive(Debug, Clone)]
struct MacroDef {
    params: Vec<MacroParam>,
    body: Vec<String>,
    wrap_scope: bool,
}

#[derive(Debug, Clone)]
struct StatementDef {
    keyword: String,
    signature: StatementSignature,
    body: Vec<String>,
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
    statements: HashMap<String, Vec<StatementDef>>,
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
            statements: HashMap::new(),
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
        let mut current_statement: Option<StatementDef> = None;
        let mut skip_statement_body = false;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx as u32 + 1;
            let (code, _) = split_comment(line);

            if let Some((name, params, kind)) = parse_macro_def_line(&code, line_num)? {
                if current.is_some() {
                    return Err(MacroError::new(
                        "Nested .macro/.segment definitions are not supported",
                        Some(line_num),
                        Some(1),
                    ));
                }
                if current_statement.is_some() {
                    return Err(MacroError::new(
                        "Nested .statement definitions are not supported",
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

            if skip_statement_body {
                if let Some(StatementDirective::End) = parse_statement_directive(&code) {
                    skip_statement_body = false;
                }
                continue;
            }

            if let Some(kind) = parse_statement_directive(&code) {
                match kind {
                    StatementDirective::Def => {
                        if current_statement.is_some() {
                            return Err(MacroError::new(
                                "Nested .statement definitions are not supported",
                                Some(line_num),
                                Some(1),
                            ));
                        }
                        if current.is_some() {
                            return Err(MacroError::new(
                                "Cannot define .statement inside .macro/.segment",
                                Some(line_num),
                                Some(1),
                            ));
                        }
                        match parse_statement_def_line(&code, line_num) {
                            Ok((keyword, signature)) => {
                                current_statement = Some(StatementDef {
                                    keyword,
                                    signature,
                                    body: Vec::new(),
                                });
                                continue;
                            }
                            Err(_) => {
                                out.push(line.clone());
                                skip_statement_body = true;
                                continue;
                            }
                        }
                    }
                    StatementDirective::End => {
                        if let Some(def) = current_statement.take() {
                            let key = to_upper(&def.keyword);
                            self.statements.entry(key).or_default().push(def);
                            continue;
                        }
                        out.push(line.clone());
                        continue;
                    }
                }
            }

            if let Some(def) = current_statement.as_mut() {
                def.body.push(line.clone());
                continue;
            }

            if let Some((name, def, _kind)) = current.as_mut() {
                let _ = name;
                def.body.push(line.clone());
                continue;
            }

            if let Some(inv) = parse_macro_invocation(&code, &self.macros, line_num)? {
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

            if let Some(expanded) = expand_statement_invocation(&code, line_num, depth, self)? {
                out.extend(expanded);
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

        if current_statement.is_some() {
            return Err(MacroError::new(
                "Missing .endstatement for statement definition",
                None,
                None,
            ));
        }

        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatementDirective {
    Def,
    End,
}

fn parse_statement_directive(code: &str) -> Option<StatementDirective> {
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
        "STATEMENT" => Some(StatementDirective::Def),
        "ENDSTATEMENT" => Some(StatementDirective::End),
        _ => None,
    }
}

fn parse_statement_def_line(code: &str, line_num: u32) -> Result<(String, StatementSignature), MacroError> {
    let mut parser = Parser::from_line(code, line_num).map_err(|err| {
        MacroError::new(err.message, Some(line_num), Some(err.span.col_start))
    })?;
    match parser.parse_line() {
        Ok(LineAst::StatementDef { keyword, signature, .. }) => Ok((keyword, signature)),
        Ok(_) => Err(MacroError::new(
            "Expected .statement definition",
            Some(line_num),
            Some(1),
        )),
        Err(err) => Err(MacroError::new(err.message, Some(line_num), Some(err.span.col_start))),
    }
}

fn expand_statement_invocation(
    code: &str,
    line_num: u32,
    depth: usize,
    processor: &mut MacroProcessor,
) -> Result<Option<Vec<String>>, MacroError> {
    if processor.statements.is_empty() {
        return Ok(None);
    }

    let mut cursor = Cursor::new(code);
    cursor.skip_ws();
    if cursor.peek().is_none() || cursor.peek() == Some(b'.') {
        return Ok(None);
    }

    let Some((label, mnemonic_text, mnemonic_end, mnemonic_col_start)) =
        scan_statement_invocation(code)
    else {
        return Ok(None);
    };

    let mnemonic_upper = mnemonic_text.to_ascii_uppercase();
    let mut expanded_match: Option<Vec<String>> = None;
    let mut matched = false;

    let statements = processor.statements.clone();
    for (keyword_upper, defs) in &statements {
        if !mnemonic_upper.starts_with(keyword_upper) {
            continue;
        }

        let remainder = &mnemonic_text[keyword_upper.len()..];
        let tail = code.get(mnemonic_end..).unwrap_or("");
        let match_text = format!("{}{}", remainder, tail);

        let match_tokens = tokenize_line(&match_text, line_num)?;
        let signatures: Vec<StatementSignature> = defs.iter().map(|def| def.signature.clone()).collect();
        let (selection, tokens_for_match) = match select_statement_signature(&signatures, &match_tokens)
            .map_err(|err| MacroError::new(err.message, Some(line_num), Some(err.span.col_start)))? {
            Some(idx) => (Some(idx), match_tokens),
            None => {
                let split_tokens = split_single_letter_digit_tokens(&match_tokens);
                let selection = select_statement_signature(&signatures, &split_tokens)
                    .map_err(|err| {
                        MacroError::new(err.message, Some(line_num), Some(err.span.col_start))
                    })?;
                (selection, split_tokens)
            }
        };

        let Some(idx) = selection else {
            continue;
        };

        let signature = &defs[idx].signature;
        let statement_match = match_statement_signature(signature, &tokens_for_match)
            .ok_or_else(|| MacroError::new("Statement signature match failed", Some(line_num), Some(1)))?;

        let args = build_statement_args(&statement_match);
        let mut expanded = Vec::new();
        for line in &defs[idx].body {
            expanded.push(substitute_line(line, &args));
        }

        if let Some(label) = &label {
            attach_label_to_expansion(label, &mut expanded);
        }

        let nested = processor.expand_lines(&expanded, depth + 1)?;
        if matched {
            return Err(MacroError::new(
                "Ambiguous statement signature",
                Some(line_num),
                Some(mnemonic_col_start),
            ));
        }
        expanded_match = Some(nested);
        matched = true;
    }

    Ok(expanded_match)
}

fn tokenize_line(line: &str, line_num: u32) -> Result<Vec<Token>, MacroError> {
    let mut tokenizer = Tokenizer::new(line, line_num);
    let mut tokens = Vec::new();
    loop {
        let token = tokenizer.next_token().map_err(|err| {
            MacroError::new(err.message, Some(line_num), Some(err.span.col_start))
        })?;
        if matches!(token.kind, TokenKind::End) {
            break;
        }
        tokens.push(token);
    }
    Ok(tokens)
}

fn split_single_letter_digit_tokens(tokens: &[Token]) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        match &token.kind {
            TokenKind::Identifier(name) | TokenKind::Register(name) => {
                if name.len() >= 2 {
                    let mut chars = name.chars();
                    if let Some(first) = chars.next() {
                        let rest: String = chars.collect();
                        if first.is_ascii_alphabetic()
                            && !rest.is_empty()
                            && rest.chars().all(|c| c.is_ascii_digit())
                        {
                            let first_kind = match &token.kind {
                                TokenKind::Identifier(_) => {
                                    TokenKind::Identifier(first.to_string())
                                }
                                TokenKind::Register(_) => TokenKind::Register(first.to_string()),
                                _ => unreachable!(),
                            };
                            let first_start = token.span.col_start;
                            let first_end = first_start + 1;
                            let second_start = first_end;
                            let second_end = token.span.col_end;
                            out.push(Token {
                                kind: first_kind,
                                span: Span {
                                    line: token.span.line,
                                    col_start: first_start,
                                    col_end: first_end,
                                },
                            });
                            out.push(Token {
                                kind: TokenKind::Number(crate::core::tokenizer::NumberLiteral {
                                    text: rest,
                                    base: 10,
                                }),
                                span: Span {
                                    line: token.span.line,
                                    col_start: second_start,
                                    col_end: second_end,
                                },
                            });
                            continue;
                        }
                    }
                }
                out.push(token.clone());
            }
            _ => out.push(token.clone()),
        }
    }
    out
}

fn scan_statement_invocation(
    line: &str,
) -> Option<(Option<String>, String, usize, usize)> {
    let mut cursor = Cursor::new(line);
    cursor.skip_ws();
    let at_col1 = cursor.pos() == 0;
    let first = cursor.peek()?;
    if first == b'.' || first == b';' || first == b'#' || first == b'*' {
        return None;
    }
    if !is_ident_start(first) {
        return None;
    }

    let mut label = None;
    if at_col1 {
        let name = cursor.take_ident()?;
        if cursor.peek() == Some(b':') {
            cursor.next();
        }
        label = Some(name);
        cursor.skip_ws();
        if cursor.peek().is_none() || !is_ident_start(cursor.peek()?) {
            return None;
        }
    }

    let mnemonic_col_start = cursor.pos() + 1;
    let mnemonic = cursor.take_ident()?;
    let mnemonic_end = cursor.pos();
    Some((label, mnemonic, mnemonic_end, mnemonic_col_start))
}

fn build_statement_args(statement_match: &crate::core::parser::StatementMatch) -> MacroArgs {
    let mut positional = Vec::new();
    let mut named = HashMap::new();
    for capture in &statement_match.captures {
        let text = capture
            .tokens
            .iter()
            .map(token_text_for_substitution)
            .collect::<String>();
        positional.push(text.clone());
        named.insert(to_upper(&capture.name), text);
    }
    let full_list = positional.join(", ");
    MacroArgs {
        positional,
        named,
        full_list,
    }
}

fn token_text_for_substitution(token: &Token) -> String {
    match &token.kind {
        TokenKind::Identifier(name) | TokenKind::Register(name) => name.clone(),
        TokenKind::Number(num) => num.text.clone(),
        TokenKind::String(lit) => lit.raw.clone(),
        TokenKind::Comma => ",".to_string(),
        TokenKind::Dot => ".".to_string(),
        TokenKind::Dollar => "$".to_string(),
        TokenKind::Hash => "#".to_string(),
        TokenKind::Question => "?".to_string(),
        TokenKind::Colon => ":".to_string(),
        TokenKind::OpenParen => "(".to_string(),
        TokenKind::CloseParen => ")".to_string(),
        TokenKind::OpenBracket => "[".to_string(),
        TokenKind::CloseBracket => "]".to_string(),
        TokenKind::OpenBrace => "{".to_string(),
        TokenKind::CloseBrace => "}".to_string(),
        TokenKind::Operator(op) => match op {
            crate::core::tokenizer::OperatorKind::Plus => "+",
            crate::core::tokenizer::OperatorKind::Minus => "-",
            crate::core::tokenizer::OperatorKind::Multiply => "*",
            crate::core::tokenizer::OperatorKind::Power => "**",
            crate::core::tokenizer::OperatorKind::Divide => "/",
            crate::core::tokenizer::OperatorKind::Mod => "%",
            crate::core::tokenizer::OperatorKind::Shl => "<<",
            crate::core::tokenizer::OperatorKind::Shr => ">>",
            crate::core::tokenizer::OperatorKind::BitNot => "~",
            crate::core::tokenizer::OperatorKind::LogicNot => "!",
            crate::core::tokenizer::OperatorKind::BitAnd => "&",
            crate::core::tokenizer::OperatorKind::BitOr => "|",
            crate::core::tokenizer::OperatorKind::BitXor => "^",
            crate::core::tokenizer::OperatorKind::LogicAnd => "&&",
            crate::core::tokenizer::OperatorKind::LogicOr => "||",
            crate::core::tokenizer::OperatorKind::LogicXor => "^^",
            crate::core::tokenizer::OperatorKind::Eq => "==",
            crate::core::tokenizer::OperatorKind::Ne => "!=",
            crate::core::tokenizer::OperatorKind::Ge => ">=",
            crate::core::tokenizer::OperatorKind::Gt => ">",
            crate::core::tokenizer::OperatorKind::Le => "<=",
            crate::core::tokenizer::OperatorKind::Lt => "<",
        }
        .to_string(),
        TokenKind::End => String::new(),
    }
}

fn attach_label_to_expansion(label: &str, expanded: &mut Vec<String>) {
    if let Some(first) = expanded.first_mut() {
        let trimmed = first.trim_start();
        if trimmed.is_empty() {
            *first = label.to_string();
        } else {
            *first = format!("{label} {trimmed}");
        }
    } else {
        expanded.push(label.to_string());
    }
}

fn parse_macro_def_line(code: &str, line_num: u32) -> Result<Option<(String, String, MacroKind)>, MacroError> {
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

fn parse_macro_invocation(
    code: &str,
    macros: &HashMap<String, MacroDef>,
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
    if cursor.peek().is_none() || !is_ident_start(cursor.peek().unwrap()) {
        return Ok(None);
    }
    let Some(name) = cursor.take_ident() else {
        return Ok(None);
    };
    if !macros.contains_key(&to_upper(&name)) {
        // If macro doesn't exist, return None to let the line pass through.
        return Ok(None);
    }

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
        name,
        args,
        full_list,
        indent,
    }))
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
                ))
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

fn parse_macro_args(text: &str, line_num: u32) -> Result<Vec<String>, MacroError> {
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
            ',' if !in_single && !in_double && paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
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

fn extract_paren_list(code: &str, start: usize, line_num: u32) -> Result<(String, usize), MacroError> {
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

fn substitute_line(line: &str, args: &MacroArgs) -> String {
    let mut out = String::new();
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
            "    lda .src".to_string(),
            "    sta .dst".to_string(),
            ".endmacro".to_string(),
            "    .COPY $12, $34".to_string(),
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
            "    .byte .first, .second".to_string(),
            ".endmacro".to_string(),
            "    .M 1".to_string(),
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
            "    .word .@".to_string(),
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
            "    .byte .val".to_string(),
            ".endsegment".to_string(),
            "    .INLINE 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 7".to_string()));
        assert!(!out.iter().any(|line| line.trim() == ".block"));
        assert!(!out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_directive_first_macro_with_paren_call() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".macro COPY(src, dst)".to_string(),
            "    lda .src".to_string(),
            "    sta .dst".to_string(),
            ".endmacro".to_string(),
            "    .COPY($12, $34)".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.contains(&"    lda $12".to_string()));
        assert!(out.contains(&"    sta $34".to_string()));
        assert!(out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_zero_arg_macro_with_and_without_parens() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "PING .macro".to_string(),
            "    .byte 1".to_string(),
            ".endmacro".to_string(),
            "    .PING".to_string(),
            "    .PING()".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.iter().filter(|line| line.trim() == ".byte 1").count() >= 2);
    }

    #[test]
    fn expands_statement_with_capture() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement LOAD byte:val".to_string(),
            "    .byte .val".to_string(),
            ".endstatement".to_string(),
            "    LOAD 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 7".to_string()));
        assert!(!out.iter().any(|line| line.trim_start().starts_with(".statement")));
    }

    #[test]
    fn expands_statement_with_keyword_parameterization() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement move.b char:dst \",\" char:src".to_string(),
            "    .byte 'b'".to_string(),
            ".endstatement".to_string(),
            "    move.b a,b".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 'b'".to_string()));
    }
}
