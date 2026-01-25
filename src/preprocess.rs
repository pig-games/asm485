// Preprocessor for #DEFINE/#IFDEF/#IFNDEF/#ELSE/#ELSEIF/#ENDIF/#INCLUDE directives.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Debug, Clone)]
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
        if !name.is_empty() {
            if !frame.any_true && defined && parent_active {
                frame.active = true;
                frame.any_true = true;
            } else {
                frame.active = false;
            }
        } else {
            frame.active = parent_active && !frame.any_true;
            frame.any_true = true;
            frame.in_else = true;
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
}

impl<'a> MacroExpander<'a> {
    fn new(macros: &'a HashMap<String, MacroDef>) -> Self {
        Self { macros }
    }

    fn expand_object_macros(&self, code: &str, depth: i32) -> String {
        if depth > 64 {
            return code.to_string();
        }
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let bytes = code.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '\'' && !in_double {
                in_single = !in_single;
            }
            if c == '"' && !in_single {
                in_double = !in_double;
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

    fn expand_line(&self, line: &str, depth: i32) -> Vec<String> {
        if depth > 64 {
            return vec![line.to_string()];
        }
        let (code, comment) = split_comment(line);
        let expanded = self.expand_object_macros(&code, depth);

        let parts = split_unquoted_backslash(&expanded);
        if parts.len() > 1 {
            let mut out = Vec::new();
            for part in parts {
                let rec = self.expand_line(&part, depth + 1);
                out.extend(rec);
            }
            if !comment.is_empty() && !out.is_empty() {
                out[0].push_str(&comment);
            }
            return out;
        }

        let mut out_lines = vec![String::new()];
        let bytes = expanded.as_bytes();
        let mut in_single = false;
        let mut in_double = false;
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '\'' && !in_double {
                in_single = !in_single;
            }
            if c == '"' && !in_single {
                in_double = !in_double;
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
                                if esc {
                                    args_str.push(ch);
                                    esc = false;
                                    p += 1;
                                    continue;
                                }
                                if ch == '\\' {
                                    esc = true;
                                    args_str.push(ch);
                                    p += 1;
                                    continue;
                                }
                                if ch == '\'' && !s_in_double {
                                    s_in_single = !s_in_single;
                                }
                                if ch == '"' && !s_in_single {
                                    s_in_double = !s_in_double;
                                }
                                if !s_in_single && !s_in_double {
                                    if ch == '(' {
                                        if paren > 0 {
                                            args_str.push(ch);
                                        }
                                        paren += 1;
                                        p += 1;
                                        continue;
                                    }
                                    if ch == ')' {
                                        paren -= 1;
                                        if paren == 0 {
                                            break;
                                        }
                                    }
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
                                if a_esc {
                                    cur.push(ch);
                                    a_esc = false;
                                    continue;
                                }
                                if ch == '\\' {
                                    a_esc = true;
                                    cur.push(ch);
                                    continue;
                                }
                                if ch == '\'' && !a_in_double {
                                    a_in_single = !a_in_single;
                                }
                                if ch == '"' && !a_in_single {
                                    a_in_double = !a_in_double;
                                }
                                if ch == ',' && !a_in_single && !a_in_double {
                                    args.push(trim(&cur).to_string());
                                    cur.clear();
                                } else {
                                    cur.push(ch);
                                }
                            }
                            if !cur.is_empty() {
                                args.push(trim(&cur).to_string());
                            }

                            let body = self.expand_function(m, &args);
                            let parts = split_unquoted_backslash(&body);
                            let mut expanded_parts = Vec::new();
                            for part in parts {
                                let rec = self.expand_line(&part, depth + 1);
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
            out_lines[0].push_str(&comment);
        }
        out_lines
    }

    fn expand_function(&self, m: &MacroDef, args: &[String]) -> String {
        let mut out = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let bytes = m.body.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '\'' && !in_double {
                in_single = !in_single;
            }
            if c == '"' && !in_single {
                in_double = !in_double;
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
                        if idx < args.len() {
                            out.push_str(&args[idx]);
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

#[derive(Debug, Default)]
pub struct Preprocessor {
    macros: HashMap<String, MacroDef>,
    cond_state: ConditionalState,
    lines: Vec<String>,
}

impl Preprocessor {
    pub fn new() -> Self {
        Self::default()
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
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            } else if line.ends_with('\r') {
                line.pop();
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
        let trimmed = ltrim(&code);
        let expander = MacroExpander::new(&self.macros);
        if trimmed.is_empty() {
            if self.is_active() {
                self.lines.push(line.to_string());
            }
            return Ok(());
        }

        let is_hash_directive = trimmed.starts_with('#');
        let leading = code.len().saturating_sub(trimmed.len());

        let mut pos = 0usize;
        let bytes = trimmed.as_bytes();
        if bytes.first() == Some(&b'#') {
            pos = 1;
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
        }
        let start = pos;
        while pos < bytes.len() && is_ident_char(bytes[pos]) {
            pos += 1;
        }
        let token = to_upper(&trimmed[start..pos]);
        let rest = trim(&trimmed[pos..]);
        let column = leading.saturating_add(start).saturating_add(1);

        let is_else_directive = token == "ELSE" || token == "ELSEIF" || token == "ENDIF";
        if is_hash_directive
            && (token == "DEFINE"
                || token == "IFDEF"
                || token == "IFNDEF"
                || token == "INCLUDE"
                || is_else_directive)
        {
            return self
                .handle_directive(&token, &rest, base_dir)
                .map_err(|err| err.with_context(line_num, Some(column), line, Some(file_path)));
        }

        if !self.is_active() {
            return Ok(());
        }
        let expanded = expander.expand_line(line, 0);
        self.lines.extend(expanded);
        Ok(())
    }

    fn handle_directive(
        &mut self,
        token: &str,
        rest: &str,
        base_dir: &str,
    ) -> Result<(), PreprocessError> {
        match token {
            "DEFINE" => {
                if !self.is_active() {
                    return Ok(());
                }
                self.handle_define(rest)
            }
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

    fn handle_define(&mut self, rest: &str) -> Result<(), PreprocessError> {
        let mut r = ltrim(rest);
        if r.is_empty() {
            return Err(PreprocessError::new("DEFINE missing name"));
        }

        let mut pos = 0usize;
        let bytes = r.as_bytes();
        while pos < bytes.len() && is_ident_char(bytes[pos]) {
            pos += 1;
        }
        let name = r[..pos].to_string();
        if name.is_empty() {
            return Err(PreprocessError::new("DEFINE missing name"));
        }
        r = ltrim(&r[pos..]);

        let mut m = MacroDef {
            is_function: false,
            params: Vec::new(),
            body: String::new(),
        };

        if r.starts_with('(') {
            let end = r.find(')');
            if end.is_none() {
                return Err(PreprocessError::new("DEFINE missing ')'"));
            }
            let end = end.unwrap();
            let params_str = &r[1..end];
            let mut params = Vec::new();
            let mut cur = String::new();
            let mut in_single = false;
            let mut in_double = false;
            let mut escape = false;
            for ch in params_str.chars() {
                if escape {
                    cur.push(ch);
                    escape = false;
                    continue;
                }
                if ch == '\\' {
                    escape = true;
                    cur.push(ch);
                    continue;
                }
                if ch == '\'' && !in_double {
                    in_single = !in_single;
                }
                if ch == '"' && !in_single {
                    in_double = !in_double;
                }
                if ch == ',' && !in_single && !in_double {
                    params.push(to_upper(&trim(&cur)));
                    cur.clear();
                } else {
                    cur.push(ch);
                }
            }
            if !cur.is_empty() {
                params.push(to_upper(&trim(&cur)));
            }
            m.is_function = true;
            m.params = params;
            m.body = trim(&r[end + 1..]).to_string();
        } else {
            m.is_function = false;
            m.body = trim(&r).to_string();
        }
        self.macros.insert(to_upper(&name), m);
        Ok(())
    }

    fn handle_ifdef(&mut self, rest: &str, negated: bool) -> Result<(), PreprocessError> {
        let name = to_upper(&trim(rest));
        if name.is_empty() {
            return Err(PreprocessError::new("IFDEF/IFNDEF missing name"));
        }
        let defined = self.is_defined(&name);
        let cond = if negated { !defined } else { defined };
        self.cond_state.push_ifdef(cond);
        Ok(())
    }

    fn handle_else(&mut self, rest: &str) -> Result<(), PreprocessError> {
        let name = to_upper(&trim(rest));
        let defined = if !name.is_empty() {
            self.is_defined(&name)
        } else {
            false
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
        let mut r = trim(rest);
        if ((r.starts_with('"') && r.ends_with('"')) || (r.starts_with('\'') && r.ends_with('\'')))
            && r.len() >= 2
        {
            r = r[1..r.len() - 1].to_string();
        }
        if r.is_empty() {
            return Err(PreprocessError::new("INCLUDE missing file"));
        }
        let path = join_path(base_dir, &r);
        self.process_file_internal(&path)
    }

    fn is_active(&self) -> bool {
        self.cond_state.is_active()
    }

    fn is_defined(&self, name: &str) -> bool {
        self.macros.contains_key(&to_upper(name))
    }

}

fn split_unquoted_backslash(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            if in_single || in_double {
                cur.push(ch);
                escape = true;
            } else {
                parts.push(cur);
                cur = String::new();
            }
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
        }
        cur.push(ch);
    }
    parts.push(cur);
    parts
}

fn split_comment(line: &str) -> (String, String) {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let c = bytes[idx] as char;
        if escape {
            escape = false;
            idx += 1;
            continue;
        }
        if c == '\\' && (in_single || in_double) {
            escape = true;
            idx += 1;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
        }
        if c == ';' && !in_single && !in_double {
            let code = line[..idx].to_string();
            let comment = line[idx..].to_string();
            return (code, comment);
        }
        idx += 1;
    }
    (line.to_string(), String::new())
}

fn trim(s: &str) -> String {
    let mut start = 0usize;
    let bytes = s.as_bytes();
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    s[start..end].to_string()
}

fn ltrim(s: &str) -> String {
    let mut start = 0usize;
    let bytes = s.as_bytes();
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    s[start..].to_string()
}

fn to_upper(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_uppercase()).collect()
}

fn is_ident_start(c: u8) -> bool {
    (c as char).is_ascii_alphabetic() || c == b'_'
}

fn is_ident_char(c: u8) -> bool {
    (c as char).is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'$'
}

fn dirname(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string())
}

fn join_path(base: &str, rel: &str) -> String {
    if rel.is_empty() {
        return base.to_string();
    }
    if rel.starts_with('/') || rel.starts_with('\\') {
        return rel.to_string();
    }
    if base.is_empty() {
        return rel.to_string();
    }
    format!("{base}/{rel}")
}

#[cfg(test)]
mod tests {
    use super::Preprocessor;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("asm485-preproc-{}", nanos));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn ifdef_selects_true_branch() {
        let path = temp_file(
            "test.asm",
            "#DEFINE FOO 1\n#IFDEF FOO\nVAL EQU 1\n#ELSE\nVAL EQU 2\n#ENDIF\n",
        );
        let mut pp = Preprocessor::new();
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].trim(), "VAL EQU 1");
    }

    #[test]
    fn function_macro_expands() {
        let path = temp_file(
            "macro.asm",
            "#DEFINE ADD(a,b) a + b\nDB ADD(1,2)\n",
        );
        let mut pp = Preprocessor::new();
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].trim(), "DB 1 + 2");
    }

    #[test]
    fn splits_unquoted_backslash() {
        let path = temp_file("split.asm", "DB 1\\DB 2\n");
        let mut pp = Preprocessor::new();
        assert!(pp.process_file(path.to_str().unwrap()).is_ok());
        let lines = pp.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].trim(), "DB 1");
        assert_eq!(lines[1].trim(), "DB 2");
    }

    #[test]
    fn reports_missing_define_name() {
        let path = temp_file("bad_define.asm", "#DEFINE\n");
        let mut pp = Preprocessor::new();
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.message(), "DEFINE missing name");
    }

    #[test]
    fn reports_else_without_ifdef() {
        let path = temp_file("bad_else.asm", "#ELSE\n");
        let mut pp = Preprocessor::new();
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.message(), "ELSE found without matching IFDEF/IFNDEF");
    }

    #[test]
    fn reports_missing_include_path() {
        let path = temp_file("bad_include.asm", "#INCLUDE\n");
        let mut pp = Preprocessor::new();
        let err = pp.process_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.message(), "INCLUDE missing file");
    }
}
