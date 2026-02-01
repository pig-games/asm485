// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Parser for tokenized assembly source.

use crate::core::expr::{parse_number, value_fits_byte, value_fits_word};
use crate::core::text_utils::is_ident_start;
use crate::core::tokenizer::{
    ConditionalKind, OperatorKind, Span, Token, TokenKind, TokenizeError, Tokenizer,
};

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum LineAst {
    Empty,
    Conditional {
        kind: ConditionalKind,
        exprs: Vec<Expr>,
        span: Span,
    },
    StatementDef {
        keyword: String,
        signature: StatementSignature,
        span: Span,
    },
    StatementEnd {
        span: Span,
    },
    Assignment {
        label: Label,
        op: AssignOp,
        expr: Expr,
        span: Span,
    },
    Statement {
        label: Option<Label>,
        mnemonic: Option<String>,
        operands: Vec<Expr>,
    },
}

#[derive(Debug, Clone)]
pub struct Label {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Number(String, Span),
    Identifier(String, Span),
    Register(String, Span),
    /// Indirect/memory reference via register: (HL), (BC), (IX+d), etc.
    /// For simple cases like (HL), the inner is Register.
    /// For indexed like (IX+5), the inner is Binary with base register.
    Indirect(Box<Expr>, Span),
    /// Immediate value: #expr
    Immediate(Box<Expr>, Span),
    /// Tuple/List: (a, b) - used for complex indirects like ($nn, X)
    Tuple(Vec<Expr>, Span),
    Dollar(Span),
    String(Vec<u8>, Span),
    Error(String, Span),
    Ternary {
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct StatementSignature {
    pub atoms: Vec<SignatureAtom>,
}

#[derive(Debug, Clone)]
pub enum SignatureAtom {
    Literal(Vec<u8>, Span),
    Capture {
        type_name: String,
        name: String,
        span: Span,
    },
    Boundary {
        atoms: Vec<SignatureAtom>,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct StatementCapture {
    pub name: String,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
pub struct StatementMatch {
    pub captures: Vec<StatementCapture>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Plus,
    Minus,
    BitNot,
    LogicNot,
    High,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    Const,
    Var,
    VarIfUndef,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    BitOr,
    BitXor,
    BitAnd,
    LogicOr,
    LogicAnd,
    Shl,
    Shr,
    Concat,
    Min,
    Max,
    Repeat,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Multiply,
    Divide,
    Mod,
    Power,
    Shl,
    Shr,
    Add,
    Subtract,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
    BitAnd,
    BitOr,
    BitXor,
    LogicAnd,
    LogicOr,
    LogicXor,
}

pub struct Parser {
    tokens: Vec<Token>,
    index: usize,
    end_span: Span,
    end_token_text: Option<String>,
}

impl Parser {
    pub fn from_line(line: &str, line_num: u32) -> Result<Self, ParseError> {
        Self::from_line_with_registers(
            line,
            line_num,
            crate::core::tokenizer::register_checker_none(),
        )
    }

    pub fn from_line_with_registers(
        line: &str,
        line_num: u32,
        is_register: crate::core::tokenizer::RegisterChecker,
    ) -> Result<Self, ParseError> {
        if let Some(first) = line.as_bytes().first().copied() {
            if !first.is_ascii_whitespace()
                && first != b';'
                && first != b'.'
                && first != b'*'
                && !is_ident_start(first)
            {
                return Err(ParseError {
                    message: format!(
                        "Illegal character in column 1. Must be symbol, '.', '*', comment, or space. Found: {}",
                        line
                    ),
                    span: Span {
                        line: line_num,
                        col_start: 1,
                        col_end: 1,
                    },
                });
            }
        }
        let mut tokenizer = Tokenizer::with_register_checker(line, line_num, is_register);
        let mut tokens = Vec::new();
        let mut end_token_text = None;
        let end_span = loop {
            let token = tokenizer.next_token().map_err(map_tokenize_error)?;
            if matches!(token.kind, TokenKind::End) {
                let idx = token.span.col_start.saturating_sub(1);
                if idx < line.len() && line.as_bytes().get(idx) == Some(&b';') {
                    end_token_text = Some(";".to_string());
                }
                break token.span;
            }
            tokens.push(token);
        };
        Ok(Self {
            tokens,
            index: 0,
            end_span,
            end_token_text,
        })
    }

    pub fn end_span(&self) -> Span {
        self.end_span
    }

    pub fn end_token_text(&self) -> Option<&str> {
        self.end_token_text.as_deref()
    }

    pub fn parse_line(&mut self) -> Result<LineAst, ParseError> {
        if self.tokens.is_empty() {
            return Ok(LineAst::Empty);
        }

        let mut label = None;
        let mut idx = 0usize;
        if let Some(first) = self.tokens.first() {
            let label_name = match &first.kind {
                TokenKind::Identifier(name) => Some(name.clone()),
                TokenKind::Register(name) => Some(name.clone()),
                _ => None,
            };
            if let Some(name) = label_name {
                if first.span.col_start == 1 {
                    if let Some(colon) = self.tokens.get(1) {
                        if matches!(colon.kind, TokenKind::Colon)
                            && colon.span.col_start == first.span.col_end
                        {
                            label = Some(Label {
                                name: name.clone(),
                                span: first.span,
                            });
                            idx = 2;
                        }
                        if label.is_none() {
                            label = Some(Label {
                                name,
                                span: first.span,
                            });
                            idx = 1;
                        }
                    } else {
                        label = Some(Label {
                            name,
                            span: first.span,
                        });
                        idx = 1;
                    }
                }
            }
        }

        self.index = idx;
        if self.index >= self.tokens.len() {
            return Ok(LineAst::Statement {
                label,
                mnemonic: None,
                operands: Vec::new(),
            });
        }

        if label.is_none() {
            if let Some(Token {
                kind: TokenKind::Operator(OperatorKind::Multiply),
                ..
            }) = self.tokens.get(self.index)
            {
                if matches!(
                    self.tokens.get(self.index + 1),
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
                    self.index = self.index.saturating_add(2);
                    let expr = self.parse_expr()?;
                    if self.index < self.tokens.len() {
                        return Err(ParseError {
                            message: "Unexpected trailing tokens".to_string(),
                            span: self.tokens[self.index].span,
                        });
                    }
                    return Ok(LineAst::Statement {
                        label,
                        mnemonic: Some(".org".to_string()),
                        operands: vec![expr],
                    });
                }
            }
        }

        if let Some(label) = &label {
            if let Some((op, span, consumed)) = self.match_assignment_op() {
                self.index = self.index.saturating_add(consumed);
                let expr = match self.parse_expr() {
                    Ok(expr) => expr,
                    Err(err) => Expr::Error(err.message, err.span),
                };
                if self.index < self.tokens.len() {
                    return Err(ParseError {
                        message: "Unexpected trailing tokens".to_string(),
                        span: self.tokens[self.index].span,
                    });
                }
                return Ok(LineAst::Assignment {
                    label: label.clone(),
                    op,
                    expr,
                    span,
                });
            }
        }

        if self.consume_kind(TokenKind::Dot) {
            let (name, span) = match self.next() {
                Some(Token {
                    kind: TokenKind::Identifier(name),
                    span,
                }) => (name, span),
                Some(Token {
                    kind: TokenKind::Register(name),
                    span,
                }) => (name, span),
                Some(token) => {
                    return Err(ParseError {
                        message: "Expected conditional after '.'".to_string(),
                        span: token.span,
                    })
                }
                None => {
                    return Err(ParseError {
                        message: "Expected conditional after '.'".to_string(),
                        span: self.end_span,
                    })
                }
            };
            let upper = name.to_ascii_uppercase();
            if upper.as_str() == "STATEMENT" {
                let start_span = span;
                let keyword = match self.next() {
                    Some(Token {
                        kind: TokenKind::Identifier(name),
                        ..
                    }) => name,
                    Some(Token {
                        kind: TokenKind::Register(name),
                        ..
                    }) => name,
                    Some(token) => {
                        return Err(ParseError {
                            message: "Expected statement keyword".to_string(),
                            span: token.span,
                        });
                    }
                    None => {
                        return Err(ParseError {
                            message: "Expected statement keyword".to_string(),
                            span: self.end_span,
                        });
                    }
                };
                let signature = self.parse_statement_signature(false)?;
                let end_span = if self.index == 0 {
                    self.end_span
                } else {
                    self.prev_span()
                };
                let span = Span {
                    line: start_span.line,
                    col_start: start_span.col_start,
                    col_end: end_span.col_end,
                };
                return Ok(LineAst::StatementDef {
                    keyword,
                    signature,
                    span,
                });
            }
            if upper.as_str() == "ENDSTATEMENT" {
                if self.index < self.tokens.len() {
                    return Err(ParseError {
                        message: "Unexpected tokens after .endstatement".to_string(),
                        span: self.tokens[self.index].span,
                    });
                }
                return Ok(LineAst::StatementEnd { span });
            }
            if matches!(
                upper.as_str(),
                "MACRO" | "SEGMENT" | "ENDMACRO" | "ENDSEGMENT" | "ENDM" | "ENDS"
            ) {
                self.index = self.tokens.len();
                return Ok(LineAst::Statement {
                    label,
                    mnemonic: Some(format!(".{name}")),
                    operands: Vec::new(),
                });
            }
            let (kind, needs_expr, list_exprs) = match upper.as_str() {
                "IF" => (ConditionalKind::If, true, false),
                "ELSEIF" => (ConditionalKind::ElseIf, true, false),
                "ELSE" => (ConditionalKind::Else, false, false),
                "ENDIF" => (ConditionalKind::EndIf, false, false),
                "MATCH" => (ConditionalKind::Switch, true, false),
                "CASE" => (ConditionalKind::Case, true, true),
                "DEFAULT" => (ConditionalKind::Default, false, false),
                "ENDMATCH" => (ConditionalKind::EndSwitch, false, false),
                _ => {
                    let mut operands = Vec::new();
                    if self.index < self.tokens.len() {
                        match self.parse_expr() {
                            Ok(expr) => operands.push(expr),
                            Err(err) => {
                                operands.push(Expr::Error(err.message, err.span));
                                return Ok(LineAst::Statement {
                                    label,
                                    mnemonic: Some(format!(".{name}")),
                                    operands,
                                });
                            }
                        }
                        while self.consume_comma() {
                            match self.parse_expr() {
                                Ok(expr) => operands.push(expr),
                                Err(err) => {
                                    operands.push(Expr::Error(err.message, err.span));
                                    return Ok(LineAst::Statement {
                                        label,
                                        mnemonic: Some(format!(".{name}")),
                                        operands,
                                    });
                                }
                            }
                        }
                    }
                    if self.index < self.tokens.len() {
                        return Err(ParseError {
                            message: "Unexpected trailing tokens".to_string(),
                            span: self.tokens[self.index].span,
                        });
                    }
                    return Ok(LineAst::Statement {
                        label,
                        mnemonic: Some(format!(".{name}")),
                        operands,
                    });
                }
            };
            let mut exprs = Vec::new();
            if needs_expr {
                match self.parse_expr() {
                    Ok(expr) => exprs.push(expr),
                    Err(err) => exprs.push(Expr::Error(err.message, err.span)),
                }
                if list_exprs {
                    while self.consume_comma() {
                        match self.parse_expr() {
                            Ok(expr) => exprs.push(expr),
                            Err(err) => {
                                exprs.push(Expr::Error(err.message, err.span));
                                break;
                            }
                        }
                    }
                }
            }
            if self.index < self.tokens.len() {
                return Err(ParseError {
                    message: "Unexpected tokens after conditional".to_string(),
                    span: self.tokens[self.index].span,
                });
            }
            return Ok(LineAst::Conditional { kind, exprs, span });
        }

        let mnemonic = match self.next() {
            Some(Token {
                kind: TokenKind::Identifier(name),
                ..
            }) => Some(name),
            Some(token) => {
                return Err(ParseError {
                    message: "Expected mnemonic identifier".to_string(),
                    span: token.span,
                });
            }
            None => None,
        };

        let mut operands = Vec::new();
        if self.index < self.tokens.len() {
            match self.parse_expr() {
                Ok(expr) => operands.push(expr),
                Err(err) => {
                    operands.push(Expr::Error(err.message, err.span));
                    return Ok(LineAst::Statement {
                        label,
                        mnemonic,
                        operands,
                    });
                }
            }
            while self.consume_comma() {
                match self.parse_expr() {
                    Ok(expr) => operands.push(expr),
                    Err(err) => {
                        operands.push(Expr::Error(err.message, err.span));
                        return Ok(LineAst::Statement {
                            label,
                            mnemonic,
                            operands,
                        });
                    }
                }
            }
        }

        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: self.tokens[self.index].span,
            });
        }

        Ok(LineAst::Statement {
            label,
            mnemonic,
            operands,
        })
    }

    fn match_assignment_op(&self) -> Option<(AssignOp, Span, usize)> {
        let token = self.tokens.get(self.index)?;
        let next = self.tokens.get(self.index + 1);
        let next2 = self.tokens.get(self.index + 2);
        match &token.kind {
            TokenKind::Operator(OperatorKind::Eq) => {
                Some((AssignOp::Const, token.span, 1))
            }
            TokenKind::Colon => {
                if matches!(next, Some(Token { kind: TokenKind::Question, .. }))
                    && matches!(next2, Some(Token { kind: TokenKind::Operator(OperatorKind::Eq), .. }))
                {
                    Some((AssignOp::VarIfUndef, token.span, 3))
                } else if matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
                    Some((AssignOp::Var, token.span, 2))
                } else {
                    None
                }
            }
            TokenKind::Operator(kind) => {
                let op = match kind {
                    OperatorKind::Plus => AssignOp::Add,
                    OperatorKind::Minus => AssignOp::Sub,
                    OperatorKind::Multiply => AssignOp::Mul,
                    OperatorKind::Divide => AssignOp::Div,
                    OperatorKind::Mod => AssignOp::Mod,
                    OperatorKind::Power => AssignOp::Pow,
                    OperatorKind::BitOr => AssignOp::BitOr,
                    OperatorKind::BitXor => AssignOp::BitXor,
                    OperatorKind::BitAnd => AssignOp::BitAnd,
                    OperatorKind::LogicOr => AssignOp::LogicOr,
                    OperatorKind::LogicAnd => AssignOp::LogicAnd,
                    OperatorKind::Shl => AssignOp::Shl,
                    OperatorKind::Shr => AssignOp::Shr,
                    OperatorKind::Lt => {
                        if matches!(next, Some(Token { kind: TokenKind::Question, .. }))
                            && matches!(next2, Some(Token { kind: TokenKind::Operator(OperatorKind::Eq), .. }))
                        {
                            return Some((AssignOp::Min, token.span, 3));
                        }
                        return None;
                    }
                    OperatorKind::Gt => {
                        if matches!(next, Some(Token { kind: TokenKind::Question, .. }))
                            && matches!(next2, Some(Token { kind: TokenKind::Operator(OperatorKind::Eq), .. }))
                        {
                            return Some((AssignOp::Max, token.span, 3));
                        }
                        return None;
                    }
                    _ => return None,
                };
                if matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
                    Some((op, token.span, 2))
                } else {
                    None
                }
            }
            TokenKind::Dot => {
                if matches!(next, Some(Token { kind: TokenKind::Dot, .. }))
                    && matches!(next2, Some(Token { kind: TokenKind::Operator(OperatorKind::Eq), .. }))
                {
                    Some((AssignOp::Concat, token.span, 3))
                } else if matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
                    Some((AssignOp::Member, token.span, 2))
                } else {
                    None
                }
            }
            TokenKind::Identifier(name) => {
                if name.eq_ignore_ascii_case("x")
                    && matches!(next, Some(Token { kind: TokenKind::Operator(OperatorKind::Eq), .. }))
                {
                    Some((AssignOp::Repeat, token.span, 2))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn parse_statement_signature(&mut self, in_boundary: bool) -> Result<StatementSignature, ParseError> {
        let mut atoms = Vec::new();
        let mut closed = !in_boundary;
        while self.index < self.tokens.len() {
            if in_boundary
                && self.peek_kind(TokenKind::CloseBrace)
                && self.peek_kind_next(TokenKind::CloseBracket)
            {
                self.index += 2;
                closed = true;
                break;
            }

            if in_boundary && self.peek_kind(TokenKind::CloseBrace) {
                let token = self.next().expect("token");
                return Err(ParseError {
                    message: "Missing closing }]".to_string(),
                    span: token.span,
                });
            }

            if self.peek_kind(TokenKind::OpenBracket)
                && self.peek_kind_next(TokenKind::OpenBrace)
            {
                let open_span = self.tokens[self.index].span;
                self.index += 2;
                let inner = self.parse_statement_signature(true)?;
                let close_span = self.prev_span();
                let span = Span {
                    line: open_span.line,
                    col_start: open_span.col_start,
                    col_end: close_span.col_end,
                };
                atoms.push(SignatureAtom::Boundary {
                    atoms: inner.atoms,
                    span,
                });
                continue;
            }

            let token = self.next().ok_or(ParseError {
                message: "Unexpected end of statement signature".to_string(),
                span: self.end_span,
            })?;
            match token.kind {
                TokenKind::String(lit) => {
                    atoms.push(SignatureAtom::Literal(lit.bytes, token.span));
                }
                TokenKind::Dot => {
                    atoms.push(SignatureAtom::Literal(vec![b'.'], token.span));
                }
                TokenKind::Comma => {
                    return Err(ParseError {
                        message: "Commas must be quoted in statement signatures".to_string(),
                        span: token.span,
                    });
                }
                TokenKind::Identifier(type_name) | TokenKind::Register(type_name) => {
                    if !is_valid_capture_type(&type_name) {
                        return Err(ParseError {
                            message: format!("Unknown statement capture type: {type_name}"),
                            span: token.span,
                        });
                    }
                    let colon = self.next().ok_or(ParseError {
                        message: "Expected ':' after capture type".to_string(),
                        span: self.end_span,
                    })?;
                    if !matches!(colon.kind, TokenKind::Colon) {
                        return Err(ParseError {
                            message: "Expected ':' after capture type".to_string(),
                            span: colon.span,
                        });
                    }
                    let next = self.next().ok_or(ParseError {
                        message: "Expected capture name after type".to_string(),
                        span: self.end_span,
                    })?;
                    let name = match next.kind {
                        TokenKind::Identifier(name) | TokenKind::Register(name) => name,
                        _ => {
                            return Err(ParseError {
                                message: "Expected capture name after type".to_string(),
                                span: next.span,
                            });
                        }
                    };
                    let span = Span {
                        line: token.span.line,
                        col_start: token.span.col_start,
                        col_end: next.span.col_end,
                    };
                    atoms.push(SignatureAtom::Capture {
                        type_name,
                        name,
                        span,
                    });
                }
                _ => {
                    return Err(ParseError {
                        message: "Unexpected token in statement signature".to_string(),
                        span: token.span,
                    });
                }
            }
        }
        if !closed {
            return Err(ParseError {
                message: "Missing closing }]".to_string(),
                span: self.end_span,
            });
        }
        Ok(StatementSignature { atoms })
    }

    fn peek_kind(&self, kind: TokenKind) -> bool {
        matches!(self.peek(), Some(Token { kind: k, .. }) if *k == kind)
    }

    fn peek_kind_next(&self, kind: TokenKind) -> bool {
        matches!(self.tokens.get(self.index + 1), Some(Token { kind: k, .. }) if *k == kind)
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        match self.peek_operator_kind() {
            Some(OperatorKind::Lt) => {
                self.index += 1;
                let span = self.prev_span();
                let expr = self.parse_expr()?;
                return Ok(Expr::Unary {
                    op: UnaryOp::Low,
                    expr: Box::new(expr),
                    span,
                });
            }
            Some(OperatorKind::Gt) => {
                self.index += 1;
                let span = self.prev_span();
                let expr = self.parse_expr()?;
                return Ok(Expr::Unary {
                    op: UnaryOp::High,
                    expr: Box::new(expr),
                    span,
                });
            }
            _ => {}
        }

        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_logical_or()?;
        if let Some(token) = self.peek() {
            if token.kind == TokenKind::Question {
                let span = token.span;
                self.index += 1;
                let then_expr = self.parse_expr()?;
                if !self.consume_kind(TokenKind::Colon) {
                    return Err(ParseError {
                        message: "Missing ':' in conditional expression".to_string(),
                        span: self.current_span(),
                    });
                }
                let else_expr = self.parse_expr()?;
                node = Expr::Ternary {
                    cond: Box::new(node),
                    then_expr: Box::new(then_expr),
                    else_expr: Box::new(else_expr),
                    span,
                };
            }
        }
        Ok(node)
    }

    fn parse_logical_or(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_logical_and()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::LogicOr) => BinaryOp::LogicOr,
                Some(OperatorKind::LogicXor) => BinaryOp::LogicXor,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_logical_and()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_logical_and(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_or()?;
        while self.match_operator(OperatorKind::LogicAnd) {
            let op_span = self.prev_span();
            let right = self.parse_bit_or()?;
            node = Expr::Binary {
                op: BinaryOp::LogicAnd,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_or(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_xor()?;
        while self.match_operator(OperatorKind::BitOr) {
            let op_span = self.prev_span();
            let right = self.parse_bit_xor()?;
            node = Expr::Binary {
                op: BinaryOp::BitOr,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_xor(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_and()?;
        while self.match_operator(OperatorKind::BitXor) {
            let op_span = self.prev_span();
            let right = self.parse_bit_and()?;
            node = Expr::Binary {
                op: BinaryOp::BitXor,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_and(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_compare()?;
        while self.match_operator(OperatorKind::BitAnd) {
            let op_span = self.prev_span();
            let right = self.parse_compare()?;
            node = Expr::Binary {
                op: BinaryOp::BitAnd,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_compare(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_shift()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Eq) => BinaryOp::Eq,
                Some(OperatorKind::Ne) => BinaryOp::Ne,
                Some(OperatorKind::Ge) => BinaryOp::Ge,
                Some(OperatorKind::Gt) => BinaryOp::Gt,
                Some(OperatorKind::Le) => BinaryOp::Le,
                Some(OperatorKind::Lt) => BinaryOp::Lt,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_shift()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_shift(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_sum()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Shl) => BinaryOp::Shl,
                Some(OperatorKind::Shr) => BinaryOp::Shr,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_sum()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_sum(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_term()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Plus) => BinaryOp::Add,
                Some(OperatorKind::Minus) => BinaryOp::Subtract,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_term()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_term(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_power()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Multiply) => BinaryOp::Multiply,
                Some(OperatorKind::Divide) => BinaryOp::Divide,
                Some(OperatorKind::Mod) => BinaryOp::Mod,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_power()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_power(&mut self) -> Result<Expr, ParseError> {
        let node = self.parse_unary()?;
        if self.match_operator(OperatorKind::Power) {
            let op_span = self.prev_span();
            let right = self.parse_power()?;
            return Ok(Expr::Binary {
                op: BinaryOp::Power,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            });
        }
        Ok(node)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if let Some(op) = match self.peek_operator_kind() {
            Some(OperatorKind::Plus) => Some(UnaryOp::Plus),
            Some(OperatorKind::Minus) => Some(UnaryOp::Minus),
            Some(OperatorKind::BitNot) => Some(UnaryOp::BitNot),
            Some(OperatorKind::LogicNot) => Some(UnaryOp::LogicNot),
            _ => None,
        } {
            self.index += 1;
            let span = self.prev_span();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary {
                op,
                expr: Box::new(expr),
                span,
            });
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.next() {
            Some(Token {
                kind: TokenKind::Hash,
                span: hash_span,
            }) => {
                // Immediate mode: #expr
                let expr = self.parse_expr()?;
                let end_span = self.prev_span();
                let span = Span {
                    line: hash_span.line,
                    col_start: hash_span.col_start,
                    col_end: end_span.col_end,
                };
                Ok(Expr::Immediate(Box::new(expr), span))
            }
            Some(Token {
                kind: TokenKind::Number(num),
                span,
            }) => Ok(Expr::Number(num.text, span)),
            Some(Token {
                kind: TokenKind::Identifier(name),
                span,
            }) => Ok(Expr::Identifier(name, span)),
            Some(Token {
                kind: TokenKind::Register(name),
                span,
            }) => Ok(Expr::Register(name, span)),
            Some(Token {
                kind: TokenKind::Dollar,
                span,
            }) => Ok(Expr::Dollar(span)),
            Some(Token {
                kind: TokenKind::String(lit),
                span,
            }) => Ok(Expr::String(lit.bytes, span)),
            Some(Token {
                kind: TokenKind::OpenParen,
                span: open_span,
            }) => {
                let expr = self.parse_expr()?;
                
                if self.consume_comma() {
                    let mut elements = vec![expr];
                    elements.push(self.parse_expr()?);
                    while self.consume_comma() {
                        elements.push(self.parse_expr()?);
                    }
                    
                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')' in tuple".to_string(),
                            span: self.current_span(),
                        });
                    }
                    let span = Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    };
                    // Wrap in Indirect to maintain consistency that (...) is grouping/indirect
                    // The handler will inspect the inner Expr::Tuple
                    Ok(Expr::Indirect(Box::new(Expr::Tuple(elements, span)), span))
                } else {
                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')'".to_string(),
                            span: self.current_span(),
                        });
                    }
                    Ok(Expr::Indirect(Box::new(expr), Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    }))
                }
            }
            Some(token) => Err(ParseError {
                message: "Unexpected token in expression".to_string(),
                span: token.span,
            }),
            None => Err(ParseError {
                message: match self.end_token_text.as_deref() {
                    Some(token) => format!("Expected label or numeric constant, found: {token}"),
                    None => "Unexpected end of expression".to_string(),
                },
                span: self.end_span,
            }),
        }
    }

    fn consume_comma(&mut self) -> bool {
        self.consume_kind(TokenKind::Comma)
    }

    fn consume_kind(&mut self, kind: TokenKind) -> bool {
        if let Some(token) = self.peek() {
            if token.kind == kind {
                self.index += 1;
                return true;
            }
        }
        false
    }

    fn match_operator(&mut self, op: OperatorKind) -> bool {
        if let Some(token) = self.peek() {
            if token.kind == TokenKind::Operator(op) {
                self.index += 1;
                return true;
            }
        }
        false
    }

    fn peek_operator_kind(&self) -> Option<OperatorKind> {
        if let Some(token) = self.peek() {
            if let TokenKind::Operator(op) = token.kind {
                return Some(op);
            }
        }
        None
    }

    fn next(&mut self) -> Option<Token> {
        if self.index >= self.tokens.len() {
            None
        } else {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            Some(token)
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn prev_span(&self) -> Span {
        if self.index == 0 {
            Span {
                line: 0,
                col_start: 0,
                col_end: 0,
            }
        } else {
            self.tokens[self.index - 1].span
        }
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.index)
            .map(|t| t.span)
            .unwrap_or(self.end_span)
    }
}

fn map_tokenize_error(err: TokenizeError) -> ParseError {
    ParseError {
        message: err.message,
        span: err.span,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignatureScore {
    literal_atoms: usize,
    atom_count: usize,
}

impl SignatureScore {
    fn better_than(self, other: Self) -> bool {
        if self.literal_atoms != other.literal_atoms {
            return self.literal_atoms > other.literal_atoms;
        }
        self.atom_count > other.atom_count
    }
}

fn signature_score(signature: &StatementSignature) -> SignatureScore {
    let mut literal_atoms = 0usize;
    for atom in &signature.atoms {
        if matches!(atom, SignatureAtom::Literal(_, _)) {
            literal_atoms += 1;
        }
    }
    SignatureScore {
        literal_atoms,
        atom_count: signature.atoms.len(),
    }
}

fn token_text(token: &Token) -> String {
    match &token.kind {
        TokenKind::Identifier(name) | TokenKind::Register(name) => name.clone(),
        TokenKind::Number(num) => num.text.clone(),
        TokenKind::String(lit) => String::from_utf8_lossy(&lit.bytes).to_string(),
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
            OperatorKind::Plus => "+",
            OperatorKind::Minus => "-",
            OperatorKind::Multiply => "*",
            OperatorKind::Power => "**",
            OperatorKind::Divide => "/",
            OperatorKind::Mod => "%",
            OperatorKind::Shl => "<<",
            OperatorKind::Shr => ">>",
            OperatorKind::BitNot => "~",
            OperatorKind::LogicNot => "!",
            OperatorKind::BitAnd => "&",
            OperatorKind::BitOr => "|",
            OperatorKind::BitXor => "^",
            OperatorKind::LogicAnd => "&&",
            OperatorKind::LogicOr => "||",
            OperatorKind::LogicXor => "^^",
            OperatorKind::Eq => "==",
            OperatorKind::Ne => "!=",
            OperatorKind::Ge => ">=",
            OperatorKind::Gt => ">",
            OperatorKind::Le => "<=",
            OperatorKind::Lt => "<",
        }
        .to_string(),
        TokenKind::End => "".to_string(),
    }
}

fn matches_literal(tokens: &[Token], start: usize, literal: &str) -> Option<(usize, Span)> {
    let mut acc = String::new();
    let mut idx = start;
    let mut last_span: Option<Span> = None;
    while idx < tokens.len() && acc.len() < literal.len() {
        let token = &tokens[idx];
        if let Some(prev) = last_span {
            if token.span.col_start != prev.col_end {
                return None;
            }
        }
        acc.push_str(&token_text(token));
        last_span = Some(token.span);
        if !literal.starts_with(&acc) {
            return None;
        }
        if acc == literal {
            return Some((idx + 1, token.span));
        }
        idx += 1;
    }
    None
}

fn match_signature_atoms(
    atoms: &[SignatureAtom],
    tokens: &[Token],
    start: usize,
    require_adjacent: bool,
    prev_span: Option<Span>,
    captures: &mut Vec<StatementCapture>,
) -> Option<(usize, Option<Span>)> {
    let mut idx = start;
    let mut last_span = prev_span;
    for atom in atoms {
        match atom {
            SignatureAtom::Literal(bytes, _) => {
                let literal = String::from_utf8_lossy(bytes).to_string();
                let (next_idx, span) = matches_literal(tokens, idx, &literal)?;
                if require_adjacent {
                    if let Some(prev) = last_span {
                        let first_span = tokens[idx].span;
                        if first_span.col_start != prev.col_end {
                            return None;
                        }
                    }
                }
                idx = next_idx;
                last_span = Some(span);
            }
            SignatureAtom::Capture { name, type_name, .. } => {
                let token = tokens.get(idx)?;
                if require_adjacent {
                    if let Some(prev) = last_span {
                        if token.span.col_start != prev.col_end {
                            return None;
                        }
                    }
                }
                if !token_matches_capture_type(type_name, token) {
                    return None;
                }
                captures.push(StatementCapture {
                    name: name.clone(),
                    tokens: vec![token.clone()],
                });
                last_span = Some(token.span);
                idx += 1;
            }
            SignatureAtom::Boundary { atoms: inner, .. } => {
                let (next_idx, inner_span) = match_signature_atoms(
                    inner,
                    tokens,
                    idx,
                    true,
                    last_span,
                    captures,
                )?;
                idx = next_idx;
                if let Some(span) = inner_span {
                    last_span = Some(span);
                }
            }
        }
    }
    Some((idx, last_span))
}

fn token_matches_capture_type(type_name: &str, token: &Token) -> bool {
    match type_name.to_ascii_lowercase().as_str() {
        "byte" => token_matches_byte(token),
        "word" => token_matches_word(token),
        "char" => token_matches_char(token),
        "str" => token_matches_str(token),
        _ => matches_any_capture_token(token),
    }
}

fn is_valid_capture_type(type_name: &str) -> bool {
    matches!(
        type_name.to_ascii_lowercase().as_str(),
        "byte" | "word" | "char" | "str"
    )
}

fn matches_any_capture_token(token: &Token) -> bool {
    matches!(
        token.kind,
        TokenKind::Identifier(_)
            | TokenKind::Register(_)
            | TokenKind::Number(_)
            | TokenKind::String(_)
    )
}

fn token_matches_byte(token: &Token) -> bool {
    match &token.kind {
        TokenKind::Number(lit) => parse_number(&lit.text)
            .is_some_and(value_fits_byte),
        TokenKind::Identifier(_) | TokenKind::Register(_) => true,
        TokenKind::String(lit) => lit.bytes.len() == 1,
        _ => false,
    }
}

fn token_matches_word(token: &Token) -> bool {
    match &token.kind {
        TokenKind::Number(lit) => parse_number(&lit.text)
            .is_some_and(value_fits_word),
        TokenKind::Identifier(_) | TokenKind::Register(_) => true,
        TokenKind::String(lit) => lit.bytes.len() == 1 || lit.bytes.len() == 2,
        _ => false,
    }
}

fn token_matches_char(token: &Token) -> bool {
    match &token.kind {
        TokenKind::Identifier(text) | TokenKind::Register(text) => text.len() == 1,
        TokenKind::String(lit) => lit.bytes.len() == 1,
        _ => false,
    }
}

fn token_matches_str(token: &Token) -> bool {
    matches!(token.kind, TokenKind::String(_))
}

pub fn match_statement_signature(
    signature: &StatementSignature,
    tokens: &[Token],
) -> Option<StatementMatch> {
    let mut captures = Vec::new();
    let (next_idx, _) = match_signature_atoms(
        &signature.atoms,
        tokens,
        0,
        false,
        None,
        &mut captures,
    )?;
    if next_idx == tokens.len() {
        Some(StatementMatch { captures })
    } else {
        None
    }
}

pub fn select_statement_signature(
    signatures: &[StatementSignature],
    tokens: &[Token],
) -> Result<Option<usize>, ParseError> {
    let mut best_idx = None;
    let mut best_score = SignatureScore {
        literal_atoms: 0,
        atom_count: 0,
    };
    let mut tied = false;

    for (idx, signature) in signatures.iter().enumerate() {
        if match_statement_signature(signature, tokens).is_none() {
            continue;
        }
        let score = signature_score(signature);
        if best_idx.is_none() || score.better_than(best_score) {
            best_idx = Some(idx);
            best_score = score;
            tied = false;
        } else if score == best_score {
            tied = true;
        }
    }

    if tied {
        let span = tokens
            .first()
            .map(|t| t.span)
            .unwrap_or(Span {
                line: 0,
                col_start: 0,
                col_end: 0,
            });
        return Err(ParseError {
            message: "Ambiguous statement signature".to_string(),
            span,
        });
    }
    Ok(best_idx)
}

#[cfg(test)]
mod tests {
    use super::{
        match_statement_signature,
        select_statement_signature,
        AssignOp,
        ConditionalKind,
        LineAst,
        Parser,
        SignatureAtom,
    };
    use crate::core::tokenizer::Tokenizer;

    fn tokenize_line(line: &str) -> Vec<crate::core::tokenizer::Token> {
        let mut tokenizer = Tokenizer::new(line, 1);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer.next_token().unwrap();
            if matches!(token.kind, crate::core::tokenizer::TokenKind::End) {
                break;
            }
            tokens.push(token);
        }
        tokens
    }

    #[test]
    fn parses_label_and_mnemonic() {
        let mut parser = Parser::from_line("LABEL: MOV A,B", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { label, mnemonic, operands } => {
                let label = label.expect("label");
                assert_eq!(label.name, "LABEL");
                assert_eq!(mnemonic.as_deref(), Some("MOV"));
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_label_without_colon() {
        let mut parser = Parser::from_line("LABEL MOV A,B", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { label, mnemonic, operands } => {
                let label = label.expect("label");
                assert_eq!(label.name, "LABEL");
                assert_eq!(mnemonic.as_deref(), Some("MOV"));
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_label_for_const() {
        let mut parser = Parser::from_line("NAME .const 3", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { label, mnemonic, operands } => {
                let label = label.expect("label");
                assert_eq!(label.name, "NAME");
                assert_eq!(mnemonic.as_deref(), Some(".const"));
                assert_eq!(operands.len(), 1);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_assignment_constant() {
        let mut parser = Parser::from_line("WIDTH = 40", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Assignment { label, op, .. } => {
                assert_eq!(label.name, "WIDTH");
                assert_eq!(op, AssignOp::Const);
            }
            _ => panic!("Expected assignment"),
        }
    }

    #[test]
    fn parses_assignment_var() {
        let mut parser = Parser::from_line("var2 := 1", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Assignment { label, op, .. } => {
                assert_eq!(label.name, "var2");
                assert_eq!(op, AssignOp::Var);
            }
            _ => panic!("Expected assignment"),
        }
    }

    #[test]
    fn parses_conditionals() {
        let mut parser = Parser::from_line(".if 1", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Conditional { kind, exprs, .. } => {
                assert_eq!(kind, ConditionalKind::If);
                assert_eq!(exprs.len(), 1);
            }
            _ => panic!("Expected conditional"),
        }
    }

    #[test]
    fn parses_switch_case_list() {
        let mut parser = Parser::from_line(".case 1, 2, 3", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Conditional { kind, exprs, .. } => {
                assert_eq!(kind, ConditionalKind::Case);
                assert_eq!(exprs.len(), 3);
            }
            _ => panic!("Expected conditional"),
        }
    }

    #[test]
    fn parses_operand_list() {
        let mut parser = Parser::from_line("    DB 1, 2, 3", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { operands, .. } => {
                assert_eq!(operands.len(), 3);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_dot_directive_statement() {
        let mut parser = Parser::from_line("    .byte 1, 2", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, operands, .. } => {
                assert_eq!(mnemonic.as_deref(), Some(".byte"));
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_macro_directive_line_without_error() {
        let mut parser = Parser::from_line(".macro COPY(src, dst)", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, .. } => {
                assert_eq!(mnemonic.as_deref(), Some(".macro"));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_name_first_macro_definition_without_error() {
        let mut parser = Parser::from_line("COPY .macro src, dst", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { label, mnemonic, .. } => {
                assert_eq!(label.map(|l| l.name), Some("COPY".to_string()));
                assert_eq!(mnemonic.as_deref(), Some(".macro"));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_segment_directive_line_without_error() {
        let mut parser = Parser::from_line(".segment INLINE(val)", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, .. } => {
                assert_eq!(mnemonic.as_deref(), Some(".segment"));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_statement_definition_with_signature() {
        let mut parser = Parser::from_line(
            ".statement move.b char:dst \",\" char:src",
            1,
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::StatementDef { keyword, signature, .. } => {
                assert_eq!(keyword, "move.b");
                assert_eq!(signature.atoms.len(), 3);
                assert!(matches!(signature.atoms[0], SignatureAtom::Capture { .. }));
                assert!(matches!(signature.atoms[1], SignatureAtom::Literal(_, _)));
                assert!(matches!(signature.atoms[2], SignatureAtom::Capture { .. }));
            }
            _ => panic!("Expected statement definition"),
        }
    }

    #[test]
    fn parses_statement_boundary_span() {
        let mut parser = Parser::from_line(
            ".statement sta \"[\" byte:a \",\"[{char:reg}]",
            1,
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::StatementDef { signature, .. } => {
                assert_eq!(signature.atoms.len(), 4);
                assert!(matches!(signature.atoms[0], SignatureAtom::Literal(_, _)));
                assert!(matches!(signature.atoms[1], SignatureAtom::Capture { .. }));
                assert!(matches!(signature.atoms[2], SignatureAtom::Literal(_, _)));
                assert!(matches!(signature.atoms[3], SignatureAtom::Boundary { .. }));
            }
            _ => panic!("Expected statement definition"),
        }
    }

    #[test]
    fn matches_statement_signature_literal_sequence() {
        let mut sig_parser = Parser::from_line(
            ".statement sta \"],y\"",
            1,
        )
        .unwrap();
        let signature = match sig_parser.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };
        assert_eq!(signature.atoms.len(), 1);
        match &signature.atoms[0] {
            SignatureAtom::Literal(bytes, _) => {
                assert_eq!(String::from_utf8_lossy(bytes), "],y");
            }
            _ => panic!("Expected literal atom"),
        }

        let mut tokenizer = Tokenizer::new("],y", 1);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer.next_token().unwrap();
            if matches!(token.kind, crate::core::tokenizer::TokenKind::End) {
                break;
            }
            tokens.push(token);
        }
        assert!(match_statement_signature(&signature, &tokens).is_some());
    }

    #[test]
    fn statement_signature_precedence_prefers_more_literals() {
        let mut parser1 = Parser::from_line(
            ".statement foo \"x\" byte:a",
            1,
        )
        .unwrap();
        let sig1 = match parser1.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };
        assert_eq!(sig1.atoms.len(), 2);
        assert!(matches!(sig1.atoms[0], SignatureAtom::Literal(_, _)));
        assert!(matches!(sig1.atoms[1], SignatureAtom::Capture { .. }));

        let mut parser2 = Parser::from_line(
            ".statement foo byte:a",
            1,
        )
        .unwrap();
        let sig2 = match parser2.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };
        assert_eq!(sig2.atoms.len(), 1);
        assert!(matches!(sig2.atoms[0], SignatureAtom::Capture { .. }));

        let mut tokenizer = Tokenizer::new("x 10", 1);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer.next_token().unwrap();
            if matches!(token.kind, crate::core::tokenizer::TokenKind::End) {
                break;
            }
            tokens.push(token);
        }

        let idx = select_statement_signature(&[sig1, sig2], &tokens)
            .expect("select")
            .expect("match");
        assert_eq!(idx, 0);
    }

    #[test]
    fn statement_signature_byte_capture_rejects_out_of_range() {
        let mut parser = Parser::from_line(
            ".statement foo byte:a",
            1,
        )
        .unwrap();
        let signature = match parser.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let ok_tokens = tokenize_line("255");
        assert!(match_statement_signature(&signature, &ok_tokens).is_some());

        let bad_tokens = tokenize_line("256");
        assert!(match_statement_signature(&signature, &bad_tokens).is_none());

        let label_tokens = tokenize_line("LABEL");
        assert!(match_statement_signature(&signature, &label_tokens).is_some());
    }

    #[test]
    fn statement_signature_word_capture_rejects_out_of_range() {
        let mut parser = Parser::from_line(
            ".statement foo word:a",
            1,
        )
        .unwrap();
        let signature = match parser.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let ok_tokens = tokenize_line("65535");
        assert!(match_statement_signature(&signature, &ok_tokens).is_some());

        let bad_tokens = tokenize_line("65536");
        assert!(match_statement_signature(&signature, &bad_tokens).is_none());

        let str_tokens = tokenize_line("\"AB\"");
        assert!(match_statement_signature(&signature, &str_tokens).is_some());
    }

    #[test]
    fn statement_signature_char_capture_requires_single_char() {
        let mut parser = Parser::from_line(
            ".statement foo char:c",
            1,
        )
        .unwrap();
        let signature = match parser.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let ok_tokens = tokenize_line("y");
        assert!(match_statement_signature(&signature, &ok_tokens).is_some());

        let bad_tokens = tokenize_line("yy");
        assert!(match_statement_signature(&signature, &bad_tokens).is_none());

        let str_tokens = tokenize_line("\"A\"");
        assert!(match_statement_signature(&signature, &str_tokens).is_some());

        let long_str_tokens = tokenize_line("\"AB\"");
        assert!(match_statement_signature(&signature, &long_str_tokens).is_none());
    }

    #[test]
    fn statement_signature_str_capture_requires_string_literal() {
        let mut parser = Parser::from_line(
            ".statement foo str:s",
            1,
        )
        .unwrap();
        let signature = match parser.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let ok_tokens = tokenize_line("\"hello\"");
        assert!(match_statement_signature(&signature, &ok_tokens).is_some());

        let bad_tokens = tokenize_line("hello");
        assert!(match_statement_signature(&signature, &bad_tokens).is_none());
    }

    #[test]
    fn statement_signature_rejects_unknown_capture_type() {
        let mut parser = Parser::from_line(
            ".statement move reg:dst",
            1,
        )
        .unwrap();
        let err = parser.parse_line().expect_err("expected error");
        assert!(err.message.contains("Unknown statement capture type"));
    }

    #[test]
    fn statement_signature_rejects_unquoted_commas() {
        let mut parser = Parser::from_line(
            ".statement move.b char:dst, char:src",
            1,
        )
        .unwrap();
        let err = parser.parse_line().expect_err("expected error");
        assert!(err
            .message
            .contains("Commas must be quoted in statement signatures"));
    }

    #[test]
    fn statement_signature_selection_reports_ambiguity() {
        let mut parser1 = Parser::from_line(
            ".statement foo byte:a",
            1,
        )
        .unwrap();
        let sig1 = match parser1.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let mut parser2 = Parser::from_line(
            ".statement foo word:b",
            1,
        )
        .unwrap();
        let sig2 = match parser2.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let mut tokenizer = Tokenizer::new("10", 1);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer.next_token().unwrap();
            if matches!(token.kind, crate::core::tokenizer::TokenKind::End) {
                break;
            }
            tokens.push(token);
        }

        let err = select_statement_signature(&[sig1, sig2], &tokens)
            .expect_err("expected ambiguity error");
        assert_eq!(err.message, "Ambiguous statement signature");
        assert_eq!(err.span.line, 1);
        assert_eq!(err.span.col_start, 1);
    }

    #[test]
    fn parses_endstatement_line() {
        let mut parser = Parser::from_line(".endstatement", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::StatementEnd { .. } => {}
            _ => panic!("Expected statement end"),
        }
    }

    #[test]
    fn parses_star_org_assignment() {
        let mut parser = Parser::from_line("* = $1000", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, operands, .. } => {
                assert_eq!(mnemonic.as_deref(), Some(".org"));
                assert_eq!(operands.len(), 1);
            }
            _ => panic!("Expected statement"),
        }
    }

}
