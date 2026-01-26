// Tokenizer for assembly source with spans.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col_start: usize,
    pub col_end: usize,
}

impl Span {
    fn new(line: u32, start: usize, end: usize) -> Self {
        Self {
            line,
            col_start: start + 1,
            col_end: end + 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Identifier(String),
    Register(String),
    Number(NumberLiteral),
    String(StringLiteral),
    Comma,
    Colon,
    Dollar,
    Dot,
    Question,
    OpenParen,
    CloseParen,
    Operator(OperatorKind),
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumberLiteral {
    pub text: String,
    pub base: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteral {
    pub raw: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorKind {
    Plus,
    Minus,
    Multiply,
    Power,
    Divide,
    Mod,
    Shl,
    Shr,
    BitNot,
    LogicNot,
    BitAnd,
    BitOr,
    BitXor,
    LogicAnd,
    LogicOr,
    LogicXor,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalKind {
    If,
    Else,
    ElseIf,
    EndIf,
    Switch,
    Case,
    Default,
    EndSwitch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct TokenizeError {
    pub message: String,
    pub span: Span,
}

pub struct Tokenizer<'a> {
    line_num: u32,
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Tokenizer<'a> {
    pub fn new(line: &'a str, line_num: u32) -> Self {
        Self {
            line_num,
            input: line.as_bytes(),
            cursor: 0,
        }
    }

    pub fn next_token(&mut self) -> Result<Token, TokenizeError> {
        self.skip_white();
        let start = self.cursor;
        let c = self.current_byte();
        match c {
            0 => {
                return Ok(Token {
                    kind: TokenKind::End,
                    span: Span::new(self.line_num, start, start),
                });
            }
            b';' => {
                self.cursor = self.input.len();
                return Ok(Token {
                    kind: TokenKind::End,
                    span: Span::new(self.line_num, start, start),
                });
            }
            _ if is_ident_start(c) => return self.scan_identifier(),
            _ if is_digit(c) => return self.scan_number(),
            b'"' | b'\'' => return self.scan_string(),
            b'.' => {
                self.cursor = self.cursor.saturating_add(1);
                return Ok(Token {
                    kind: TokenKind::Dot,
                    span: Span::new(self.line_num, start, self.cursor),
                });
            }
            b'?' => {
                self.cursor = self.cursor.saturating_add(1);
                return Ok(Token {
                    kind: TokenKind::Question,
                    span: Span::new(self.line_num, start, self.cursor),
                });
            }
            b'$' => {
                if is_hex_digit(self.peek_raw_byte(1)) || self.peek_raw_byte(1) == b'_' {
                    return self.scan_prefixed_number(16);
                }
                self.cursor = self.cursor.saturating_add(1);
                return Ok(Token {
                    kind: TokenKind::Dollar,
                    span: Span::new(self.line_num, start, self.cursor),
                });
            }
            b'%' => {
                let next = self.peek_raw_byte(1);
                if is_bin_digit(next) && self.is_prefix_context(start) {
                    return self.scan_prefixed_number(2);
                }
                self.cursor = self.cursor.saturating_add(1);
                return Ok(Token {
                    kind: TokenKind::Operator(OperatorKind::Mod),
                    span: Span::new(self.line_num, start, self.cursor),
                });
            }
            _ => {}
        }

        self.cursor = self.cursor.saturating_add(1);
        let kind = match c {
            b',' => TokenKind::Comma,
            b':' => TokenKind::Colon,
            b'(' => TokenKind::OpenParen,
            b')' => TokenKind::CloseParen,
            b'+' => TokenKind::Operator(OperatorKind::Plus),
            b'-' => TokenKind::Operator(OperatorKind::Minus),
            b'*' => {
                if self.peek_raw_byte(0) == b'*' {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Power)
                } else {
                    TokenKind::Operator(OperatorKind::Multiply)
                }
            }
            b'/' => TokenKind::Operator(OperatorKind::Divide),
            b'~' => TokenKind::Operator(OperatorKind::BitNot),
            b'=' => {
                if self.peek_raw_byte(0) == b'=' {
                    self.cursor = self.cursor.saturating_add(1);
                }
                TokenKind::Operator(OperatorKind::Eq)
            }
            b'!' => {
                if self.peek_raw_byte(0) == b'=' {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Ne)
                } else {
                    TokenKind::Operator(OperatorKind::LogicNot)
                }
            }
            b'&' => {
                if self.peek_raw_byte(0) == b'&' {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::LogicAnd)
                } else {
                    TokenKind::Operator(OperatorKind::BitAnd)
                }
            }
            b'|' => {
                if self.peek_raw_byte(0) == b'|' {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::LogicOr)
                } else {
                    TokenKind::Operator(OperatorKind::BitOr)
                }
            }
            b'^' => {
                if self.peek_raw_byte(0) == b'^' {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::LogicXor)
                } else {
                    TokenKind::Operator(OperatorKind::BitXor)
                }
            }
            b'<' => match self.peek_raw_byte(0) {
                b'<' => {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Shl)
                }
                b'=' => {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Le)
                }
                b'>' => {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Ne)
                }
                _ => TokenKind::Operator(OperatorKind::Lt),
            },
            b'>' => match self.peek_raw_byte(0) {
                b'>' => {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Shr)
                }
                b'=' => {
                    self.cursor = self.cursor.saturating_add(1);
                    TokenKind::Operator(OperatorKind::Ge)
                }
                _ => TokenKind::Operator(OperatorKind::Gt),
            },
            _ => {
                return Err(TokenizeError {
                    message: "Illegal character".to_string(),
                    span: Span::new(self.line_num, start, self.cursor),
                })
            }
        };
        Ok(Token {
            kind,
            span: Span::new(self.line_num, start, self.cursor),
        })
    }

    fn scan_identifier(&mut self) -> Result<Token, TokenizeError> {
        let start = self.cursor;
        while is_ident_char(self.current_byte()) {
            self.cursor = self.cursor.saturating_add(1);
        }
        let text = String::from_utf8_lossy(&self.input[start..self.cursor]).to_string();
        let upper = text.to_ascii_uppercase();

        let kind = if is_register(&upper) {
            TokenKind::Register(text)
        } else {
            TokenKind::Identifier(text)
        };

        Ok(Token {
            kind,
            span: Span::new(self.line_num, start, self.cursor),
        })
    }

    fn scan_number(&mut self) -> Result<Token, TokenizeError> {
        let start = self.cursor;
        while is_num_char(self.current_byte()) {
            self.cursor = self.cursor.saturating_add(1);
        }
        let text = String::from_utf8_lossy(&self.input[start..self.cursor]).to_string();
        let upper = text.to_ascii_uppercase();
        let (digits, base) = match upper.chars().last() {
            Some('H') => (upper[..upper.len() - 1].to_string(), 16),
            Some('B') => (upper[..upper.len() - 1].to_string(), 2),
            Some('O') | Some('Q') => (upper[..upper.len() - 1].to_string(), 8),
            Some('D') => (upper[..upper.len() - 1].to_string(), 10),
            _ => (upper, 10),
        };
        if digits.is_empty() {
            return Err(TokenizeError {
                message: "Illegal character in constant".to_string(),
                span: Span::new(self.line_num, start, self.cursor),
            });
        }

        Ok(Token {
            kind: TokenKind::Number(NumberLiteral { text, base }),
            span: Span::new(self.line_num, start, self.cursor),
        })
    }

    fn scan_prefixed_number(&mut self, base: u32) -> Result<Token, TokenizeError> {
        let start = self.cursor;
        self.cursor = self.cursor.saturating_add(1);
        let mut saw_digit = false;
        loop {
            let c = self.current_byte();
            let ok = match base {
                2 => is_bin_digit(c) || c == b'_',
                16 => is_hex_digit(c) || c == b'_',
                _ => false,
            };
            if !ok {
                break;
            }
            if c != b'_' {
                saw_digit = true;
            }
            self.cursor = self.cursor.saturating_add(1);
        }
        if !saw_digit {
            return Err(TokenizeError {
                message: "Illegal character in constant".to_string(),
                span: Span::new(self.line_num, start, self.cursor),
            });
        }
        let text = String::from_utf8_lossy(&self.input[start..self.cursor]).to_string();
        Ok(Token {
            kind: TokenKind::Number(NumberLiteral { text, base }),
            span: Span::new(self.line_num, start, self.cursor),
        })
    }

    fn scan_string(&mut self) -> Result<Token, TokenizeError> {
        let start = self.cursor;
        let quote = self.current_byte();
        self.cursor = self.cursor.saturating_add(1);
        let mut out = Vec::new();
        while self.current_byte() != 0 && self.current_byte() != quote {
            let c = self.current_byte();
            if c == b'\\' {
                self.cursor = self.cursor.saturating_add(1);
                let esc = self.current_byte();
                let val = match esc {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'0' => b'\0',
                    b'x' => {
                        let hi = self.peek_raw_byte(1);
                        let lo = self.peek_raw_byte(2);
                        if hi == 0 || lo == 0 || !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                            return Err(TokenizeError {
                                message: format!(
                                    "Bad hex escape in string: {}",
                                    String::from_utf8_lossy(&self.input[self.cursor..])
                                ),
                                span: Span::new(self.line_num, start, self.cursor),
                            });
                        }
                        self.cursor = self.cursor.saturating_add(2);
                        (hex_digit(hi) << 4) | hex_digit(lo)
                    }
                    _ => esc,
                };
                out.push(val);
            } else {
                out.push(c);
            }
            self.cursor = self.cursor.saturating_add(1);
        }

        if self.current_byte() != quote {
            return Err(TokenizeError {
                message: format!(
                    "Unterminated string: {}",
                    String::from_utf8_lossy(&self.input[start..])
                ),
                span: Span::new(self.line_num, start, self.cursor),
            });
        }
        self.cursor = self.cursor.saturating_add(1);
        let raw = String::from_utf8_lossy(&self.input[start..self.cursor]).to_string();
        Ok(Token {
            kind: TokenKind::String(StringLiteral { raw, bytes: out }),
            span: Span::new(self.line_num, start, self.cursor),
        })
    }

    fn skip_white(&mut self) {
        while is_space(self.current_byte()) {
            self.cursor = self.cursor.saturating_add(1);
        }
    }

    fn current_byte(&self) -> u8 {
        if self.cursor >= self.input.len() {
            0
        } else {
            self.input[self.cursor]
        }
    }

    fn peek_raw_byte(&self, offset: usize) -> u8 {
        let idx = self.cursor.saturating_add(offset);
        if idx >= self.input.len() {
            0
        } else {
            self.input[idx]
        }
    }

    fn is_prefix_context(&self, start: usize) -> bool {
        match self.prev_non_space(start) {
            None => true,
            Some(ch) => matches!(
                ch,
                b'(' | b',' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'~'
                    | b'!' | b'<' | b'>' | b'=' | b'?' | b':'
            ),
        }
    }

    fn prev_non_space(&self, start: usize) -> Option<u8> {
        let mut idx = start;
        while idx > 0 {
            idx = idx.saturating_sub(1);
            let c = self.input[idx];
            if !is_space(c) {
                return Some(c);
            }
        }
        None
    }
}

fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn is_ident_start(c: u8) -> bool {
    (c as char).is_ascii_alphabetic() || c == b'_'
}

fn is_digit(c: u8) -> bool {
    (c as char).is_ascii_digit()
}

fn is_alnum(c: u8) -> bool {
    (c as char).is_ascii_alphanumeric()
}

fn is_num_char(c: u8) -> bool {
    is_alnum(c) || c == b'_'
}

fn is_ident_char(c: u8) -> bool {
    is_alnum(c) || c == b'_' || c == b'.' || c == b'$'
}

fn is_bin_digit(c: u8) -> bool {
    c == b'0' || c == b'1'
}

fn is_hex_digit(c: u8) -> bool {
    (c as char).is_ascii_hexdigit()
}

fn is_register(ident: &str) -> bool {
    matches!(
        ident,
        "A" | "B" | "C" | "D" | "E" | "H" | "L" | "M" | "SP" | "PSW"
    )
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        _ => c - b'a' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::{OperatorKind, TokenKind, Tokenizer};

    #[test]
    fn tokenizes_identifier_and_register() {
        let mut tok = Tokenizer::new("MOV A,B", 1);
        assert!(matches!(tok.next_token().unwrap().kind, TokenKind::Identifier(_)));
        assert!(matches!(tok.next_token().unwrap().kind, TokenKind::Register(_)));
        assert!(matches!(tok.next_token().unwrap().kind, TokenKind::Comma));
        assert!(matches!(tok.next_token().unwrap().kind, TokenKind::Register(_)));
    }

    #[test]
    fn tokenizes_number_suffix() {
        let mut tok = Tokenizer::new("DB 0A6h", 1);
        let _ = tok.next_token().unwrap();
        let num = tok.next_token().unwrap();
        assert!(matches!(num.kind, TokenKind::Number(_)));
    }

    #[test]
    fn tokenizes_string_literal() {
        let mut tok = Tokenizer::new("DB \"A\\n\"", 1);
        let _ = tok.next_token().unwrap();
        let lit = tok.next_token().unwrap();
        if let TokenKind::String(lit) = lit.kind {
            assert_eq!(lit.bytes, vec![b'A', b'\n']);
        } else {
            panic!("Expected string literal token");
        }
    }

    #[test]
    fn tokenizes_conditionals() {
        let mut tok = Tokenizer::new(".if 1", 1);
        let t = tok.next_token().unwrap();
        assert_eq!(t.kind, TokenKind::Dot);
        let t = tok.next_token().unwrap();
        assert!(matches!(t.kind, TokenKind::Identifier(_)));
    }

    #[test]
    fn tokenizes_logic_ops() {
        let mut tok = Tokenizer::new("A && B", 1);
        let _ = tok.next_token().unwrap();
        let op = tok.next_token().unwrap();
        assert_eq!(op.kind, TokenKind::Operator(OperatorKind::LogicAnd));
    }

    #[test]
    fn tokenizes_prefixed_numbers() {
        let mut tok = Tokenizer::new("$1f + %1010", 1);
        let t = tok.next_token().unwrap();
        assert!(matches!(t.kind, TokenKind::Number(_)));
        let _ = tok.next_token().unwrap();
        let t = tok.next_token().unwrap();
        assert!(matches!(t.kind, TokenKind::Number(_)));
    }
}
