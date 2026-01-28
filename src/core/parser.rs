// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Parser for tokenized assembly source.

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
        Self::from_line_with_registers(line, line_num, crate::core::tokenizer::no_registers)
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
            let (kind, needs_expr, list_exprs) = match upper.as_str() {
                "IF" => (ConditionalKind::If, true, false),
                "ELSEIF" => (ConditionalKind::ElseIf, true, false),
                "ELSE" => (ConditionalKind::Else, false, false),
                "ENDIF" => (ConditionalKind::EndIf, false, false),
                "SWITCH" => (ConditionalKind::Switch, true, false),
                "CASE" => (ConditionalKind::Case, true, true),
                "DEFAULT" => (ConditionalKind::Default, false, false),
                "ENDSWITCH" => (ConditionalKind::EndSwitch, false, false),
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
            // Also accept register tokens as mnemonics since some CPUs have mnemonics
            // that look like register names (e.g., "IN", "JP" on Z80 where "P" is a flag)
            Some(Token {
                kind: TokenKind::Register(name),
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

#[cfg(test)]
mod tests {
    use super::{AssignOp, ConditionalKind, LineAst, Parser};

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

    #[test]
    fn parses_z80_add_with_byte() {
        use super::Expr;
        use crate::z80::is_register as is_register_z80;
        
        // Note: mnemonic not at column 1 (spaces at start) to avoid being parsed as label
        let mut parser = Parser::from_line_with_registers("        add a, 5", 1, is_register_z80).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, operands, .. } => {
                assert_eq!(mnemonic.as_deref(), Some("add"));
                println!("Operands: {:?}", operands);
                assert_eq!(operands.len(), 2);
                assert!(matches!(&operands[0], Expr::Register(name, _) if name == "a"));
                assert!(matches!(&operands[1], Expr::Number(_, _)));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_z80_condition_codes() {
        use super::Expr;
        use crate::z80::is_register as is_register_z80;
        
        let mut parser = Parser::from_line_with_registers("        jp nz, 1000h", 1, is_register_z80).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, operands, .. } => {
                assert_eq!(mnemonic.as_deref(), Some("jp"));
                println!("Operands: {:?}", operands);
                // Should have NZ as register and 1000h as number
                assert_eq!(operands.len(), 2);
                assert!(matches!(&operands[0], Expr::Register(name, _) if name.to_ascii_uppercase() == "NZ"), "Expected NZ register, got {:?}", operands[0]);
                assert!(matches!(&operands[1], Expr::Number(_, _)));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_z80_memory_operand() {
        use crate::z80::is_register as is_register_z80;
        
        let mut parser = Parser::from_line_with_registers("        ld (hl), a", 1, is_register_z80).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement { mnemonic, operands, .. } => {
                assert_eq!(mnemonic.as_deref(), Some("ld"));
                // Note: (HL) syntax currently parses as HL (parentheses are stripped)
                // This is a limitation - proper Z80 (HL) syntax support would need parser changes
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }
}
