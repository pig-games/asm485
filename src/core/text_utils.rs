// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Shared text utilities for tokenization and parsing.

/// Check if a byte is a valid identifier start character (letter or underscore).
#[inline]
pub fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

/// Check if a byte is a valid identifier continuation character.
#[inline]
pub fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'$'
}

/// Check if a byte is whitespace (space or tab).
#[inline]
pub fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Convert a string to uppercase ASCII.
#[inline]
pub fn to_upper(s: &str) -> String {
    s.to_ascii_uppercase()
}

/// Split a line into code and comment parts at the first unquoted semicolon.
pub fn split_comment(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let c = bytes[idx];
        match c {
            _ if escape => {
                escape = false;
            }
            b'\\' if in_single || in_double => {
                escape = true;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
            }
            b'"' if !in_single => {
                in_double = !in_double;
            }
            b';' if !in_single && !in_double => {
                return (&line[..idx], &line[idx..]);
            }
            _ => {}
        }
        idx += 1;
    }
    (line, "")
}

/// A simple cursor for scanning text byte-by-byte.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor at the start of the input.
    pub fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    /// Create a new cursor starting at a specific position.
    pub fn with_pos(input: &'a str, pos: usize) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos,
        }
    }

    /// Get the current position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Skip whitespace characters.
    pub fn skip_ws(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            self.pos += 1;
        }
    }

    /// Peek at the current byte without advancing.
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume and return the current byte.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    /// Try to consume an identifier, returning it if found.
    pub fn take_ident(&mut self) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ident_start() {
        assert!(is_ident_start(b'a'));
        assert!(is_ident_start(b'Z'));
        assert!(is_ident_start(b'_'));
        assert!(!is_ident_start(b'0'));
        assert!(!is_ident_start(b'.'));
    }

    #[test]
    fn test_is_ident_char() {
        assert!(is_ident_char(b'a'));
        assert!(is_ident_char(b'0'));
        assert!(is_ident_char(b'_'));
        assert!(is_ident_char(b'.'));
        assert!(is_ident_char(b'$'));
        assert!(!is_ident_char(b' '));
    }

    #[test]
    fn test_split_comment() {
        assert_eq!(split_comment("code ; comment"), ("code ", "; comment"));
        assert_eq!(split_comment("no comment"), ("no comment", ""));
        assert_eq!(split_comment("\"str;ing\" ; comment"), ("\"str;ing\" ", "; comment"));
        assert_eq!(split_comment("'c;har' ; comment"), ("'c;har' ", "; comment"));
    }

    #[test]
    fn test_cursor_take_ident() {
        let mut cursor = Cursor::new("  foo bar");
        cursor.skip_ws();
        assert_eq!(cursor.take_ident(), Some("foo".to_string()));
        cursor.skip_ws();
        assert_eq!(cursor.take_ident(), Some("bar".to_string()));
    }
}
