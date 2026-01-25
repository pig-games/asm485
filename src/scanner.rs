// Scanner/tokenizer for assembly source.

const BUFFER_SIZE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Error,
    Eof,
    Label,
    Register,
    Identifier,
    Constant,
    String,
    Comma,
    Dollar,
    OpenParen,
    CloseParen,
    BitNotOper,
    IsolateOper,
    FactorOper,
    SumOper,
    RelateOper,
    BitAndOper,
    BitOrOper,
    LogicNotOper,
    LogicAndOper,
    LogicOrOper,
    Conditional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValue {
    None = 0,
    Or = 1,
    Xor = 2,
    And = 3,
    Plus = 4,
    Minus = 5,
    Multiply = 6,
    Divide = 7,
    Mod = 8,
    Shl = 9,
    Shr = 10,
    Name = 11,
    Label = 12,
    Eq = 13,
    Ne = 14,
    Ge = 15,
    Gt = 16,
    Le = 17,
    Lt = 18,
    High = 19,
    Low = 20,
    If = 21,
    Else = 22,
    ElseIf = 23,
    EndIf = 24,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenType,
    pub value: i32,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub text: String,
}

impl Token {
    fn new() -> Self {
        Self {
            kind: TokenType::Eof,
            value: TokenValue::None as i32,
            len: 0,
            bytes: Vec::new(),
            text: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct Scanner {
    token: Token,
    line: [u8; BUFFER_SIZE],
    cursor: usize,
    error_msg: String,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            token: Token::new(),
            line: [0u8; BUFFER_SIZE],
            cursor: 0,
            error_msg: String::new(),
        }
    }

    pub fn init(&mut self, line: &str) -> TokenType {
        self.error_msg.clear();
        self.token.bytes.clear();
        self.token.text.clear();
        self.token.kind = TokenType::Identifier;
        self.token.value = TokenValue::None as i32;
        self.token.len = 0;

        self.line = [0u8; BUFFER_SIZE];
        let bytes = line.as_bytes();
        let len = bytes.len().min(BUFFER_SIZE - 1);
        self.line[..len].copy_from_slice(&bytes[..len]);
        self.cursor = 0;

        let c0 = self.current_byte();
        if is_alpha(c0) || c0 == b'_' {
            let t = self.scan_identifier();
            if t == TokenType::Error {
                self.failure(
                    "Illegal character in label.  Must be alphanum or underscore.",
                    None,
                );
            } else {
                let next = self.current_byte();
                if next == b':' || is_space(next) {
                    self.token.kind = TokenType::Label;
                    self.token.value = if next == b':' {
                        TokenValue::Label as i32
                    } else {
                        TokenValue::Name as i32
                    };
                    self.cursor = self.cursor.saturating_add(1);
                } else {
                    self.token.value = 0;
                    self.failure("Label must end with ':' or space or tab character.", None);
                }
            }
            return self.token.kind;
        }

        if !is_space_column(c0) && c0 != b';' && c0 != b'\0' {
            let rest = self.remaining_text();
            return self.failure(
                "Illegal character in column 1.  Must be label, name, comment, or space. Found",
                Some(&rest),
            );
        }

        self.token.kind = TokenType::Identifier;
        self.next_token()
    }

    pub fn next_token(&mut self) -> TokenType {
        if self.token.kind == TokenType::Error {
            return TokenType::Error;
        }
        if self.token.kind == TokenType::Eof {
            return TokenType::Eof;
        }

        self.skip_white();
        let c = self.current_byte();
        if is_alpha(c) || c == b'_' {
            self.scan_identifier();
        } else if is_digit(c) {
            self.scan_constant();
        } else if c == b'"' || c == b'\'' {
            self.scan_string();
        } else {
            let mut twochar = false;
            self.token.value = 0;
            match c {
                b';' | b'\0' => self.token.kind = TokenType::Eof,
                b',' => self.token.kind = TokenType::Comma,
                b'$' => self.token.kind = TokenType::Dollar,
                b'(' => self.token.kind = TokenType::OpenParen,
                b')' => self.token.kind = TokenType::CloseParen,
                b'^' => {
                    self.token.kind = TokenType::BitOrOper;
                    self.token.value = TokenValue::Xor as i32;
                }
                b'+' => {
                    self.token.kind = TokenType::SumOper;
                    self.token.value = TokenValue::Plus as i32;
                }
                b'-' => {
                    self.token.kind = TokenType::SumOper;
                    self.token.value = TokenValue::Minus as i32;
                }
                b'*' => {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Multiply as i32;
                }
                b'/' => {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Divide as i32;
                }
                b'%' => {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Mod as i32;
                }
                b'~' => {
                    self.token.kind = TokenType::BitNotOper;
                    self.token.value = TokenValue::Mod as i32;
                }
                b'=' => {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Eq as i32;
                }
                b'|' => {
                    if self.peek_raw_byte(1) == b'|' {
                        self.token.kind = TokenType::LogicOrOper;
                        twochar = true;
                    } else {
                        self.token.kind = TokenType::BitOrOper;
                    }
                    self.token.value = TokenValue::Or as i32;
                }
                b'&' => {
                    if self.peek_raw_byte(1) == b'&' {
                        self.token.kind = TokenType::LogicAndOper;
                        twochar = true;
                    } else {
                        self.token.kind = TokenType::BitAndOper;
                    }
                    self.token.value = TokenValue::And as i32;
                }
                b'<' => {
                    if self.peek_raw_byte(1) == b'<' {
                        self.token.kind = TokenType::FactorOper;
                        self.token.value = TokenValue::Shl as i32;
                        twochar = true;
                    } else {
                        self.token.kind = TokenType::Error;
                        let rest = self.remaining_text();
                        self.failure("Illegal character", Some(&rest));
                    }
                }
                b'>' => {
                    if self.peek_raw_byte(1) == b'>' {
                        self.token.kind = TokenType::FactorOper;
                        self.token.value = TokenValue::Shr as i32;
                        twochar = true;
                    } else {
                        self.token.kind = TokenType::Error;
                        let rest = self.remaining_text();
                        self.failure("Illegal character", Some(&rest));
                    }
                }
                _ => {
                    self.token.kind = TokenType::Error;
                    let rest = self.remaining_text();
                    self.failure("Illegal character", Some(&rest));
                }
            }

            self.token.bytes.clear();
            self.token.text.clear();
            self.token.bytes.push(c);
            self.cursor = self.cursor.saturating_add(1);
            if twochar {
                let c2 = self.current_byte();
                self.token.bytes.push(c2);
                self.cursor = self.cursor.saturating_add(1);
            }
            self.token.text = String::from_utf8_lossy(&self.token.bytes).to_string();
            self.token.len = self.token.bytes.len();
        }

        self.token.kind
    }

    pub fn change_register_to_id(&mut self) {
        if self.token.kind == TokenType::Register {
            self.token.kind = TokenType::Identifier;
        }
    }

    pub fn skip_to_end(&mut self) {
        self.token.kind = TokenType::Eof;
    }

    pub fn is_end(&self) -> bool {
        self.token.kind == TokenType::Eof
    }

    pub fn peek_char(&mut self) -> u8 {
        self.skip_white();
        self.current_byte()
    }

    pub fn get_type(&self) -> TokenType {
        self.token.kind
    }

    pub fn get_value(&self) -> i32 {
        self.token.value
    }

    pub fn get_string(&self) -> &str {
        &self.token.text
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    pub fn get_error_msg(&self) -> &str {
        &self.error_msg
    }

    fn scan_identifier(&mut self) -> TokenType {
        self.token.bytes.clear();
        while is_ident_char(self.current_byte()) && self.token.bytes.len() < BUFFER_SIZE - 1 {
            self.token.bytes.push(self.current_byte());
            self.cursor = self.cursor.saturating_add(1);
        }
        self.token.text = String::from_utf8_lossy(&self.token.bytes).to_string();

        let upper = self.token.text.to_ascii_uppercase();
        if upper.len() == 1 {
            let c0 = upper.as_bytes()[0];
            if b"ABCDEHLM".contains(&c0) {
                self.token.kind = TokenType::Register;
                self.token.value = TokenValue::None as i32;
                self.token.len = self.token.bytes.len();
                return self.token.kind;
            }
        }
        if upper == "SP" || upper == "PSW" {
            self.token.kind = TokenType::Register;
            self.token.value = TokenValue::None as i32;
            self.token.len = self.token.bytes.len();
            return self.token.kind;
        }

        self.token.kind = TokenType::Identifier;
        self.token.value = TokenValue::None as i32;

        let bytes = upper.as_bytes();
        let c0 = bytes.first().copied().unwrap_or(b'\0');
        let c1 = bytes.get(1).copied().unwrap_or(b'\0');
        let c2 = bytes.get(2).copied().unwrap_or(b'\0');

        match c0 {
            b'A' => {
                if upper == "AND" {
                    self.token.kind = TokenType::LogicAndOper;
                }
            }
            b'E' => {
                if c1 == b'Q' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Eq as i32;
                } else if upper == "ENDIF" {
                    self.token.kind = TokenType::Conditional;
                    self.token.value = TokenValue::EndIf as i32;
                } else if upper == "ELSE" {
                    self.token.kind = TokenType::Conditional;
                    self.token.value = TokenValue::Else as i32;
                } else if upper == "ELSEIF" {
                    self.token.kind = TokenType::Conditional;
                    self.token.value = TokenValue::ElseIf as i32;
                }
            }
            b'G' => {
                if c1 == b'E' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Ge as i32;
                } else if c1 == b'T' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Gt as i32;
                }
            }
            b'H' => {
                if upper == "HIGH" {
                    self.token.kind = TokenType::IsolateOper;
                    self.token.value = TokenValue::High as i32;
                }
            }
            b'I' => {
                if c1 == b'F' && c2 == b'\0' {
                    self.token.kind = TokenType::Conditional;
                    self.token.value = TokenValue::If as i32;
                }
            }
            b'L' => {
                if c1 == b'E' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Le as i32;
                } else if c1 == b'T' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Lt as i32;
                } else if upper == "LOW" {
                    self.token.kind = TokenType::IsolateOper;
                    self.token.value = TokenValue::Low as i32;
                }
            }
            b'M' => {
                if upper == "MOD" {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Mod as i32;
                }
            }
            b'N' => {
                if c1 == b'E' && c2 == b'\0' {
                    self.token.kind = TokenType::RelateOper;
                    self.token.value = TokenValue::Ne as i32;
                } else if upper == "NOT" {
                    self.token.kind = TokenType::LogicNotOper;
                }
            }
            b'O' => {
                if c1 == b'R' && c2 == b'\0' {
                    self.token.kind = TokenType::LogicOrOper;
                    self.token.value = TokenValue::Or as i32;
                }
            }
            b'S' => {
                if upper == "SHL" {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Shl as i32;
                } else if upper == "SHR" {
                    self.token.kind = TokenType::FactorOper;
                    self.token.value = TokenValue::Shr as i32;
                }
            }
            b'X' => {
                if upper == "XOR" {
                    self.token.kind = TokenType::LogicOrOper;
                    self.token.value = TokenValue::Xor as i32;
                }
            }
            _ => {}
        }

        self.token.len = self.token.bytes.len();
        self.token.kind
    }

    fn scan_constant(&mut self) -> TokenType {
        self.token.bytes.clear();
        while is_alnum(self.current_byte()) && self.token.bytes.len() < BUFFER_SIZE - 1 {
            self.token.bytes.push(self.current_byte());
            self.cursor = self.cursor.saturating_add(1);
        }
        self.token.text = String::from_utf8_lossy(&self.token.bytes).to_string();

        if self.token.bytes.is_empty() {
            return self.failure("Illegal character in decimal constant", None);
        }

        let last = self.token.bytes[self.token.bytes.len() - 1].to_ascii_uppercase();
        let base = if last == b'H' {
            16
        } else if last == b'D' || is_digit(last) {
            10
        } else if last == b'B' {
            2
        } else if last == b'O' || last == b'Q' {
            8
        } else if last == b'A' || last == b'C' || last == b'E' || last == b'F' {
            let text = self.token.text.clone();
            return self.failure(
                "Bad numeric constant.  Hex constants must end with 'H'",
                Some(&text),
            );
        } else {
            let text = self.token.text.clone();
            return self.failure("Illegal character in decimal constant", Some(&text));
        };

        let mut digits_len = self.token.bytes.len();
        if matches!(last, b'H' | b'D' | b'B' | b'O' | b'Q') {
            digits_len = digits_len.saturating_sub(1);
        }
        let digits = &self.token.bytes[..digits_len];
        let digits_str = String::from_utf8_lossy(digits);
        let value = i32::from_str_radix(&digits_str, base).unwrap_or(0);

        // Validate digits according to base, excluding suffix.
        for &ch in digits.iter() {
            let ok = match base {
                10 => is_digit(ch),
                2 => ch == b'0' || ch == b'1',
                8 => (b'0'..=b'7').contains(&ch),
                16 => is_hex_digit(ch),
                _ => false,
            };
            if !ok {
                let msg = match base {
                    10 => "Illegal character in decimal constant",
                    2 => "Illegal character in binary constant",
                    8 => "Illegal character in octal constant",
                    16 => "Illegal character in hex constant",
                    _ => "Illegal character in constant",
                };
                let text = self.token.text.clone();
                return self.failure(msg, Some(&text));
            }
        }

        self.token.kind = TokenType::Constant;
        self.token.value = value;
        self.token.len = self.token.bytes.len();
        self.token.kind
    }

    fn scan_string(&mut self) -> TokenType {
        self.token.bytes.clear();
        self.token.text.clear();
        self.token.len = 0;
        self.token.kind = TokenType::String;
        self.token.value = 0;

        let quote = self.current_byte();
        let start_cursor = self.cursor;
        self.cursor = self.cursor.saturating_add(1);
        let mut escape = false;

        while self.current_byte() != b'\0' {
            let c = self.current_byte();
            if escape {
                let out = match c {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'0' => b'\0',
                    b'x' => {
                        let c1 = self.peek_raw_byte(1);
                        let c2 = self.peek_raw_byte(2);
                        if is_hex_digit(c1) && is_hex_digit(c2) {
                            self.cursor = self.cursor.saturating_add(1);
                            let hi = hex_digit(self.current_byte());
                            self.cursor = self.cursor.saturating_add(1);
                            let lo = hex_digit(self.current_byte());
                            (hi << 4) | lo
                        } else {
                            let rest = self.remaining_text();
                            return self.failure("Bad hex escape in string", Some(&rest));
                        }
                    }
                    _ => c,
                };
                self.token.bytes.push(out);
                self.cursor = self.cursor.saturating_add(1);
                escape = false;
                continue;
            }

            if c == b'\\' {
                escape = true;
                self.cursor = self.cursor.saturating_add(1);
                continue;
            }
            if c == quote {
                break;
            }
            self.token.bytes.push(c);
            self.cursor = self.cursor.saturating_add(1);
        }

        if self.current_byte() != quote {
            let rest = self.slice_from(start_cursor);
            return self.failure("Unterminated string", Some(&rest));
        }

        self.cursor = self.cursor.saturating_add(1);
        self.token.len = self.token.bytes.len();
        self.token.text = String::from_utf8_lossy(&self.token.bytes).to_string();
        self.token.kind
    }

    fn skip_white(&mut self) {
        while self.current_byte() == b' ' || self.current_byte() == b'\t' {
            self.cursor = self.cursor.saturating_add(1);
        }
    }

    fn failure(&mut self, msg: &str, param: Option<&str>) -> TokenType {
        self.token.kind = TokenType::Error;
        self.token.value = TokenValue::None as i32;
        self.error_msg = match param {
            Some(p) => format!("{msg}: {p}"),
            None => msg.to_string(),
        };
        self.token.kind
    }

    fn current_byte(&self) -> u8 {
        self.line.get(self.cursor).copied().unwrap_or(b'\0')
    }

    fn peek_raw_byte(&self, offset: usize) -> u8 {
        self.line.get(self.cursor + offset).copied().unwrap_or(b'\0')
    }

    fn remaining_text(&self) -> String {
        self.slice_from(self.cursor)
    }

    fn slice_from(&self, start: usize) -> String {
        let mut end = start;
        while end < self.line.len() && self.line[end] != b'\0' {
            end += 1;
        }
        String::from_utf8_lossy(&self.line[start..end]).to_string()
    }
}

impl Iterator for Scanner {
    type Item = TokenType;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.next_token();
        if token == TokenType::Eof {
            None
        } else {
            Some(token)
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn is_space_column(c: u8) -> bool {
    (c as char).is_ascii_whitespace()
}

fn is_alpha(c: u8) -> bool {
    (c as char).is_ascii_alphabetic()
}

fn is_digit(c: u8) -> bool {
    (c as char).is_ascii_digit()
}

fn is_alnum(c: u8) -> bool {
    (c as char).is_ascii_alphanumeric()
}

fn is_hex_digit(c: u8) -> bool {
    (c as char).is_ascii_hexdigit()
}

fn is_ident_char(c: u8) -> bool {
    is_alnum(c) || c == b'_' || c == b'.' || c == b'$'
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
    use super::{Scanner, TokenType};

    #[test]
    fn label_and_mnemonic_tokens() {
        let mut scanner = Scanner::new();
        let t = scanner.init("LABEL: MOV A,B");
        assert_eq!(t, TokenType::Label);
        assert_eq!(scanner.get_string(), "LABEL");

        assert_eq!(scanner.next_token(), TokenType::Identifier);
        assert_eq!(scanner.get_string(), "MOV");
        assert_eq!(scanner.next_token(), TokenType::Register);
        assert_eq!(scanner.get_string(), "A");
        assert_eq!(scanner.next_token(), TokenType::Comma);
        assert_eq!(scanner.next_token(), TokenType::Register);
        assert_eq!(scanner.get_string(), "B");
    }

    #[test]
    fn parses_hex_constant() {
        let mut scanner = Scanner::new();
        let t = scanner.init("    MVI A, 0a6h");
        assert_eq!(t, TokenType::Identifier);
        assert_eq!(scanner.get_string(), "MVI");
        assert_eq!(scanner.next_token(), TokenType::Register);
        assert_eq!(scanner.get_string(), "A");
        assert_eq!(scanner.next_token(), TokenType::Comma);
        assert_eq!(scanner.next_token(), TokenType::Constant);
        assert_eq!(scanner.get_value(), 0x0a6);
    }

    #[test]
    fn string_escapes_are_decoded() {
        let mut scanner = Scanner::new();
        let t = scanner.init("    DB \"A\\n\\x2a\"");
        assert_eq!(t, TokenType::Identifier);
        assert_eq!(scanner.get_string(), "DB");
        assert_eq!(scanner.next_token(), TokenType::String);
        let token = scanner.token();
        assert_eq!(token.len, 3);
        assert_eq!(token.bytes, vec![b'A', b'\n', b'*']);
    }
}
