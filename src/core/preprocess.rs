// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Preprocessor for .IFDEF/.IFNDEF/.ELSE/.ELSEIF/.ENDIF/.INCLUDE directives.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::core::text_utils::{is_ident_char, is_ident_start, split_comment, to_upper, Cursor};

#[derive(Debug)]
pub struct PreprocessError {
    message: String,
    line: Option<u32>,
    column: Option<usize>,
    source: Option<String>,
    file: Option<String>,
}

impl PreprocessError {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            line: None,
            column: None,
            source: None,
            file: None,
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

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    fn with_context(
        mut self,
        line: u32,
        column: Option<usize>,
        source: &str,
        file: Option<&str>,
    ) -> Self {
        if self.line.is_none() {
            self.line = Some(line);
            self.column = column;
            self.source = Some(source.to_string());
            self.file = file.map(|f| f.to_string());
        }
        self
    }
}

impl fmt::Display for PreprocessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PreprocessError {}

#[derive(Debug, Clone)]
struct MacroDef {
    is_function: bool,
    params: Vec<String>,
    body: String,
}

#[derive(Debug, Clone)]
struct CondFrame {
    active: bool,
    any_true: bool,
    in_else: bool,
}

#[derive(Debug, Default)]
struct ConditionalState {
    stack: Vec<CondFrame>,
}

impl ConditionalState {
    fn clear(&mut self) {
        self.stack.clear();
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    fn is_active(&self) -> bool {
        self.stack.iter().all(|frame| frame.active)
    }

    fn push_ifdef(&mut self, cond: bool) {
        let parent_active = self.is_active();
        let frame = CondFrame {
            any_true: cond,
            active: parent_active && cond,
            in_else: false,
        };
        self.stack.push(frame);
    }

    fn handle_else(&mut self, name: &str, defined: bool) -> Result<(), PreprocessError> {
        if self.stack.is_empty() {
            return Err(PreprocessError::new(
                "ELSE found without matching IFDEF/IFNDEF",
            ));
        }
        let parent_active = self
            .stack
            .iter()
            .take(self.stack.len().saturating_sub(1))
            .all(|frame| frame.active);
        if self.stack.last().unwrap().in_else {
            return Err(PreprocessError::new("ELSE found after ELSE"));
        }

        let frame = self.stack.last_mut().unwrap();
        if name.is_empty() {
            frame.active = parent_active && !frame.any_true;
            frame.any_true = true;
            frame.in_else = true;
        } else if !frame.any_true && defined && parent_active {
            frame.active = true;
            frame.any_true = true;
        } else {
            frame.active = false;
        }
        Ok(())
    }

    fn handle_endif(&mut self) -> Result<(), PreprocessError> {
        if self.stack.is_empty() {
            return Err(PreprocessError::new(
                "ENDIF found without matching IFDEF/IFNDEF",
            ));
        }
        self.stack.pop();
        Ok(())
    }
}

struct MacroExpander<'a> {
    macros: &'a HashMap<String, MacroDef>,
    max_depth: usize,
}

impl<'a> MacroExpander<'a> {
    fn new(macros: &'a HashMap<String, MacroDef>, max_depth: usize) -> Self {
        Self { macros, max_depth }
    }

    fn expand_object_macros(&self, code: &str) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let bytes = code.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            match c {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                _ => {}
            }
            if !in_single && !in_double && is_ident_start(bytes[i]) {
                let mut j = i + 1;
                while j < bytes.len() && is_ident_char(bytes[j]) {
                    j += 1;
                }
                let tok = &code[i..j];
                if let Some(m) = self.macros.get(&to_upper(tok)) {
                    if !m.is_function {
                        out.push_str(&m.body);
                        i = j;
                        continue;
                    }
                }
                out.push_str(tok);
                i = j;
            } else {
                out.push(c);
                i += 1;
            }
        }
        out
    }

    fn expand_line(&self, line: &str, depth: usize) -> Result<Vec<String>, PreprocessError> {
        if depth > self.max_depth {
            return Err(PreprocessError::new(format!(
                "Preprocessor macro expansion exceeded maximum depth ({})",
                self.max_depth
            )));
        }
        let (code, comment) = split_comment(line);
        let expanded = self.expand_object_macros(code);

        let parts = split_unquoted_backslash(&expanded);
        if parts.len() > 1 {
            let mut out = Vec::new();
            for part in parts {
                let rec = self.expand_line(&part, depth + 1)?;
                out.extend(rec);
            }
            if !comment.is_empty() && !out.is_empty() {
                out[0].push_str(comment);
            }
            return Ok(out);
        }

        let mut out_lines = vec![String::new()];
        let bytes = expanded.as_bytes();
        let mut in_single = false;
        let mut in_double = false;
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            match c {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                _ => {}
            }
            if !in_single && !in_double && is_ident_start(bytes[i]) {
                let mut j = i + 1;
                while j < bytes.len() && is_ident_char(bytes[j]) {
                    j += 1;
                }
                let tok = &expanded[i..j];
                if let Some(m) = self.macros.get(&to_upper(tok)) {
                    if m.is_function {
                        let mut k = j;
                        while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
                            k += 1;
                        }
                        if k < bytes.len() && bytes[k] == b'(' {
                            let mut paren = 0i32;
                            let mut args_str = String::new();
                            let mut p = k;
                            let mut s_in_single = false;
                            let mut s_in_double = false;
                            let mut esc = false;
                            while p < bytes.len() {
                                let ch = bytes[p] as char;
                                match ch {
                                    _ if esc => {
                                        args_str.push(ch);
                                        esc = false;
                                        p += 1;
                                        continue;
                                    }
                                    '\\' => {
                                        esc = true;
                                        args_str.push(ch);
                                        p += 1;
                                        continue;
                                    }
                                    '\'' if !s_in_double => {
                                        s_in_single = !s_in_single;
                                    }
                                    '"' if !s_in_single => {
                                        s_in_double = !s_in_double;
                                    }
                                    '(' if !s_in_single && !s_in_double => {
                                        if paren > 0 {
                                            args_str.push(ch);
                                        }
                                        paren += 1;
                                        p += 1;
                                        continue;
                                    }
                                    ')' if !s_in_single && !s_in_double => {
                                        paren -= 1;
                                        if paren == 0 {
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                                if paren > 0 {
                                    args_str.push(ch);
                                }
                                p += 1;
                            }
                            if p >= bytes.len() {
                                out_lines.last_mut().unwrap().push_str(tok);
                                i = j;
                                continue;
                            }

                            let mut args = Vec::new();
                            let mut cur = String::new();
                            let mut a_in_single = false;
                            let mut a_in_double = false;
                            let mut a_esc = false;
                            for ch in args_str.chars() {
                                match ch {
                                    _ if a_esc => {
                                        cur.push(ch);
                                        a_esc = false;
                                    }
                                    '\\' => {
                                        a_esc = true;
                                        cur.push(ch);
                                    }
                                    '\'' if !a_in_double => {
                                        a_in_single = !a_in_single;
                                        cur.push(ch);
                                    }
                                    '"' if !a_in_single => {
                                        a_in_double = !a_in_double;
                                        cur.push(ch);
                                    }
                                    ',' if !a_in_single && !a_in_double => {
                                        args.push(trim(&cur).to_string());
                                        cur.clear();
                                    }
                                    _ => cur.push(ch),
                                }
                            }
                            if !cur.is_empty() {
                                args.push(trim(&cur).to_string());
                            }

                            let body = self.expand_function(m, &args);
                            let parts = split_unquoted_backslash(&body);
                            let mut expanded_parts = Vec::new();
                            for part in parts {
                                let rec = self.expand_line(&part, depth + 1)?;
                                expanded_parts.extend(rec);
                            }
                            if !expanded_parts.is_empty() {
                                out_lines
                                    .last_mut()
                                    .unwrap()
                                    .push_str(&expanded_parts[0]);
                                for part in expanded_parts.iter().skip(1) {
                                    out_lines.push(part.clone());
                                }
                            }
                            i = p + 1;
                            continue;
                        }
                    }
                }
                out_lines.last_mut().unwrap().push_str(tok);
                i = j;
            } else {
                out_lines.last_mut().unwrap().push(c);
                i += 1;
            }
        }
        if !comment.is_empty() {
            out_lines[0].push_str(comment);
        }
        Ok(out_lines)
    }

    fn expand_function(&self, m: &MacroDef, args: &[String]) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let bytes = m.body.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            match c {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                _ => {}
            }
            if !in_single && !in_double && is_ident_start(bytes[i]) {
                let mut j = i + 1;
                while j < bytes.len() && is_ident_char(bytes[j]) {
                    j += 1;
                }
                let tok = &m.body[i..j];
                let up = to_upper(tok);
                let mut replaced = false;
                for (idx, param) in m.params.iter().enumerate() {
                    if up == *param {
                        if let Some(value) = args.get(idx) {
                            out.push_str(value);
                        }
                        replaced = true;
                        break;
                    }
                }
                if !replaced {
                    out.push_str(tok);
                }
                i = j;
            } else {
                out.push(c);
                i += 1;
            }
        }
        out
    }
}

#[derive(Debug)]
pub struct Preprocessor {
    macros: HashMap<String, MacroDef>,
    cond_state: ConditionalState,
    lines: Vec<String>,
    in_asm_macro: bool,
    max_depth: usize,
}

impl Preprocessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            macros: HashMap::new(),
            cond_state: ConditionalState::default(),
            lines: Vec::new(),
            in_asm_macro: false,
            max_depth,
        }
    }

    pub fn define(&mut self, name: &str, value: &str) {
        let m = MacroDef {
            is_function: false,
            params: Vec::new(),
            body: value.to_string(),
        };
        self.macros.insert(to_upper(name), m);
    }

    pub fn process_file(&mut self, path: &str) -> Result<(), PreprocessError> {
        self.lines.clear();
        self.cond_state.clear();
        self.in_asm_macro = false;
        self.process_file_internal(path)
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    fn process_file_internal(&mut self, path: &str) -> Result<(), PreprocessError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Err(PreprocessError::new(format!(
                    "Error opening file: {path}"
                )))
            }
        };
        let base_dir = dirname(path);
        let mut reader = io::BufReader::new(file);
        let mut line = String::new();
        let mut line_num: u32 = 0;
        loop {
            line.clear();
            let read = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => {
                    return Err(PreprocessError::new(format!(
                        "Error opening file: {path}"
                    )))
                }
            };
            if read == 0 {
                break;
            }
            line_num = line_num.saturating_add(1);
            match line.as_bytes().last() {
                Some(b'\n') => {
                    line.pop();
                    if line.as_bytes().last() == Some(&b'\r') {
                        line.pop();
                    }
                }
                Some(b'\r') => {
                    line.pop();
                }
                _ => {}
            }
            self.process_line(&line, &base_dir, line_num, path)?;
        }
        Ok(())
    }

    fn process_line(
        &mut self,
        line: &str,
        base_dir: &str,
        line_num: u32,
        file_path: &str,
    ) -> Result<(), PreprocessError> {
        let (code, _comment) = split_comment(line);
        let trimmed = ltrim(code);
        let asm_macro_directive = parse_asm_macro_directive(trimmed);
        let next_in_asm_macro = match asm_macro_directive {
            Some(AsmMacroDirective::Start) => true,
            Some(AsmMacroDirective::End) => false,
            None => self.in_asm_macro,
        };
        let expander = MacroExpander::new(&self.macros, self.max_depth);
        if trimmed.is_empty() {
            if self.is_active() {
                self.lines.push(line.to_string());
            }
            return Ok(());
        }

        let is_hash_directive = trimmed.starts_with('#');
        let is_dot_directive = trimmed.starts_with('.');
        let leading = code.len().saturating_sub(trimmed.len());

        let mut pos = 0usize;
        let bytes = trimmed.as_bytes();
        match bytes.first() {
            Some(b'#') | Some(b'.') => {
                pos = 1;
                while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
            }
            _ => {}
        }
        let start = pos;
        while pos < bytes.len() && is_ident_char(bytes[pos]) {
            pos += 1;
        }
        let token = to_upper(&trimmed[start..pos]);
        let rest = trim(&trimmed[pos..]);
        let column = leading.saturating_add(start).saturating_add(1);

        let is_else_directive = token == "ELSE" || token == "ELSEIF" || token == "ENDIF";
        let is_pp_directive = token == "IFDEF"
            || token == "IFNDEF"
            || token == "INCLUDE"
            || is_else_directive;
        if is_hash_directive && is_pp_directive {
            let err = PreprocessError::new("Preprocessor directives must use '.'");
            return Err(err.with_context(line_num, Some(column), line, Some(file_path)));
        }
        if is_dot_directive && is_pp_directive {
            if is_else_directive && self.cond_state.is_empty() {
                // Pass through .else/.elseif/.endif for assembler conditionals.
            } else {
                return self
                    .handle_directive(&token, rest, base_dir)
                    .map_err(|err| err.with_context(line_num, Some(column), line, Some(file_path)));
            }
        }

        if self.in_asm_macro || asm_macro_directive.is_some() {
            if self.is_active() {
                self.lines.push(line.to_string());
            }
            self.in_asm_macro = next_in_asm_macro;
            return Ok(());
        }

        if !self.is_active() {
            self.in_asm_macro = next_in_asm_macro;
            return Ok(());
        }
        let expanded = expander
            .expand_line(line, 0)
            .map_err(|err| err.with_context(line_num, None, line, Some(file_path)))?;
        self.lines.extend(expanded);
        self.in_asm_macro = next_in_asm_macro;
        Ok(())
    }

    fn handle_directive(
        &mut self,
        token: &str,
        rest: &str,
        base_dir: &str,
    ) -> Result<(), PreprocessError> {
        match token {
            "IFDEF" => self.handle_ifdef(rest, false),
            "IFNDEF" => self.handle_ifdef(rest, true),
            "ELSE" | "ELSEIF" => self.handle_else(rest),
            "ENDIF" => self.handle_endif(),
            "INCLUDE" => {
                if !self.is_active() {
                    return Ok(());
                }
                self.handle_include(rest, base_dir)
            }
            _ => Ok(()),
        }
    }

    fn handle_ifdef(&mut self, rest: &str, negated: bool) -> Result<(), PreprocessError> {
        let name = to_upper(trim(rest));
        if name.is_empty() {
            return Err(PreprocessError::new("IFDEF/IFNDEF missing name"));
        }
        let defined = self.is_defined(&name);
        let cond = match negated {
            true => !defined,
            false => defined,
        };
        self.cond_state.push_ifdef(cond);
        Ok(())
    }

    fn handle_else(&mut self, rest: &str) -> Result<(), PreprocessError> {
        let name = to_upper(trim(rest));
        let defined = if name.is_empty() {
            false
        } else {
            self.is_defined(&name)
        };
        self.cond_state.handle_else(&name, defined)?;
        Ok(())
    }

    fn handle_endif(&mut self) -> Result<(), PreprocessError> {
        self.cond_state.handle_endif()?;
        Ok(())
    }

    fn handle_include(&mut self, rest: &str, base_dir: &str) -> Result<(), PreprocessError> {
        if !self.is_active() {
            return Ok(());
        }
        let r = trim(rest);
        let r = match (r.as_bytes().first(), r.as_bytes().last()) {
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\'')) if r.len() >= 2 => {
                &r[1..r.len() - 1]
            }
            _ => r,
        };
        if r.is_empty() {
            return Err(PreprocessError::new("INCLUDE missing file"));
        }
        let path = join_path(base_dir, r);
        self.process_file_internal(&path)
    }

    fn is_active(&self) -> bool {
        self.cond_state.is_active()
    }

    fn is_defined(&self, name: &str) -> bool {
        self.macros.contains_key(&to_upper(name))
    }

}

impl Default for Preprocessor {
    fn default() -> Self {
        Self {
            macros: HashMap::new(),
            cond_state: ConditionalState::default(),
            lines: Vec::new(),
            in_asm_macro: false,
            max_depth: 64,
        }
    }
}

fn split_unquoted_backslash(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for ch in s.chars() {
        match ch {
            _ if escape => {
                cur.push(ch);
                escape = false;
            }
            '\\' if in_single || in_double => {
                cur.push(ch);
                escape = true;
            }
            '\\' => {
                parts.push(cur);
                cur = String::new();
            }
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(ch);
            }
            _ => cur.push(ch),
        }
    }
    parts.push(cur);
    parts
}

fn trim(s: &str) -> &str {
    s.trim()
}

fn ltrim(s: &str) -> &str {
    s.trim_start()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsmMacroDirective {
    Start,
    End,
}

fn parse_asm_macro_directive(trimmed: &str) -> Option<AsmMacroDirective> {
    let mut cursor = Cursor::new(trimmed);
    cursor.skip_ws();
    cursor.peek()?;
    match cursor.peek() {
        Some(b'.') => {
            cursor.next();
        }
        Some(ch) if is_ident_start(ch) => {
            cursor.take_ident()?;
            if let Some(b':') = cursor.peek() {
                cursor.next();
            }
            cursor.skip_ws();
            match cursor.peek() {
                Some(b'.') => {
                    cursor.next();
                }
                _ => return None,
            }
        }
        _ => return None,
    }

    cursor.skip_ws();
    let directive = cursor.take_ident()?.to_ascii_uppercase();
    match directive.as_str() {
        "MACRO" | "SEGMENT" | "STATEMENT" => Some(AsmMacroDirective::Start),
        "ENDMACRO" | "ENDM" | "ENDSEGMENT" | "ENDS" | "ENDSTATEMENT" => {
            Some(AsmMacroDirective::End)
        }
        _ => None,
    }
}

fn dirname(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string())
}

fn join_path(base: &str, rel: &str) -> String {
    match rel {
        "" => base.to_string(),
        _ if rel.starts_with('/') || rel.starts_with('\\') => rel.to_string(),
        _ if base.is_empty() => rel.to_string(),
        _ => format!("{base}/{rel}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{MacroDef, MacroExpander, Preprocessor};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("opForge-preproc-{}", nanos));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn ifdef_selects_true_branch() {
        let path = temp_file(
            "test.asm",
            ".IFDEF FOO\nVAL .const 1\n.ELSE\nVAL .const 2\n.ENDIF\n",
        );
        let mut pp = Preprocessor::new();
        pp.define("FOO", "1");
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].trim(), "VAL .const 1");
    }

    #[test]
    fn object_macro_expands() {
        let path = temp_file(
            "macro.asm",
            ".byte ADD\n",
        );
        let mut pp = Preprocessor::new();
        pp.define("ADD", "1 + 2");
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].trim(), ".byte 1 + 2");
    }

    #[test]
    fn splits_unquoted_backslash() {
        let path = temp_file("split.asm", ".byte 1\\.byte 2\n");
        let mut pp = Preprocessor::new();
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].trim(), ".byte 1");
        assert_eq!(lines[1].trim(), ".byte 2");
    }

    #[test]
    fn passes_through_else_when_no_preproc_block() {
        let path = temp_file("else_pass.asm", ".ELSE\n");
        let mut pp = Preprocessor::new();
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].trim(), ".ELSE");
    }

    #[test]
    fn reports_missing_include_path() {
        let path = temp_file("bad_include.asm", ".INCLUDE\n");
        let mut pp = Preprocessor::new();
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.message(), "INCLUDE missing file");
    }

    #[test]
    fn rejects_hash_directives() {
        let path = temp_file("hash_directive.asm", "#IFDEF FOO\n");
        let mut pp = Preprocessor::new();
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.message(), "Preprocessor directives must use '.'");
    }

    #[test]
    fn macro_expansion_depth_errors() {
        let mut macros = HashMap::new();
        macros.insert(
            "F".to_string(),
            MacroDef {
                is_function: true,
                params: vec!["X".to_string()],
                body: "F(X)".to_string(),
            },
        );
        let expander = MacroExpander::new(&macros, 1);
        let err = expander.expand_line("F(1)", 0).unwrap_err();
        assert!(err.message().contains("maximum depth"));
    }

    #[test]
    fn preprocessor_macro_depth_errors_with_low_limit() {
        let path = temp_file("depth.asm", "X\n");
        let mut pp = Preprocessor::with_max_depth(1);
        pp.define("X", "X\\X");
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.message().contains("maximum depth"));
    }
}
