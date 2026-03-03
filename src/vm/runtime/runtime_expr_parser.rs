use crate::core::parser::{BinaryOp, Expr, ParseError, UnaryOp};
use crate::core::tokenizer::{OperatorKind, Span, Token, TokenKind};

pub(super) struct RuntimeExpressionParser {
    tokens: Vec<Token>,
    index: usize,
    end_span: Span,
    end_token_text: Option<String>,
}

impl RuntimeExpressionParser {
    pub(super) fn new(tokens: Vec<Token>, end_span: Span, end_token_text: Option<String>) -> Self {
        Self {
            tokens,
            index: 0,
            end_span,
            end_token_text,
        }
    }

    pub(super) fn parse_expr_from_tokens(mut self) -> Result<Expr, ParseError> {
        let expr = self.parse_expr()?;
        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: self.tokens[self.index].span,
            });
        }
        Ok(expr)
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
        let mut node = self.parse_range()?;
        while self.match_operator(OperatorKind::BitAnd) {
            let op_span = self.prev_span();
            let right = self.parse_range()?;
            node = Expr::Binary {
                op: BinaryOp::BitAnd,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_range(&mut self) -> Result<Expr, ParseError> {
        let start = self.parse_compare()?;
        let (inclusive, op_span) = match self.peek_operator_kind() {
            Some(OperatorKind::Range) => {
                self.index += 1;
                (false, self.prev_span())
            }
            Some(OperatorKind::RangeInclusive) => {
                self.index += 1;
                (true, self.prev_span())
            }
            _ => return Ok(start),
        };

        let end = self.parse_compare()?;
        let step = if self.consume_kind(TokenKind::Colon) {
            Some(Box::new(self.parse_compare()?))
        } else {
            None
        };

        Ok(Expr::Range {
            start: Box::new(start),
            end: Box::new(end),
            step,
            inclusive,
            span: op_span,
        })
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
        let base = match self.next() {
            Some(Token {
                kind: TokenKind::Hash,
                span: hash_span,
            }) => {
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
                kind: TokenKind::Question,
                span,
            }) => Ok(Expr::Placeholder(span)),
            Some(Token {
                kind: TokenKind::Dot,
                span: dot_span,
            }) => {
                let name = match self.next() {
                    Some(Token {
                        kind: TokenKind::Identifier(name),
                        ..
                    })
                    | Some(Token {
                        kind: TokenKind::Register(name),
                        ..
                    }) => name,
                    Some(token) => {
                        return Err(ParseError {
                            message: "Expected function name after '.'".to_string(),
                            span: token.span,
                        })
                    }
                    None => {
                        return Err(ParseError {
                            message: "Expected function name after '.'".to_string(),
                            span: self.end_span,
                        })
                    }
                };
                if !self.consume_kind(TokenKind::OpenParen) {
                    return Err(ParseError {
                        message: "Expected '(' after function name".to_string(),
                        span: self.current_span(),
                    });
                }
                let mut args = Vec::new();
                if !self.consume_kind(TokenKind::CloseParen) {
                    args.push(self.parse_expr()?);
                    while self.consume_comma() {
                        args.push(self.parse_expr()?);
                    }
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')' in function call".to_string(),
                            span: self.current_span(),
                        });
                    }
                }
                let end_span = self.prev_span();
                Ok(Expr::Call {
                    name: format!(".{name}"),
                    args,
                    span: Span {
                        line: dot_span.line,
                        col_start: dot_span.col_start,
                        col_end: end_span.col_end,
                    },
                })
            }
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
                    Ok(Expr::Indirect(Box::new(Expr::Tuple(elements, span)), span))
                } else {
                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')'".to_string(),
                            span: self.current_span(),
                        });
                    }
                    Ok(Expr::Indirect(
                        Box::new(expr),
                        Span {
                            line: open_span.line,
                            col_start: open_span.col_start,
                            col_end: close_span.col_end,
                        },
                    ))
                }
            }
            Some(Token {
                kind: TokenKind::OpenBracket,
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
                    if !self.consume_kind(TokenKind::CloseBracket) {
                        return Err(ParseError {
                            message: "Missing ']' in tuple".to_string(),
                            span: self.current_span(),
                        });
                    }
                    let span = Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    };
                    Ok(Expr::IndirectLong(
                        Box::new(Expr::Tuple(elements, span)),
                        span,
                    ))
                } else {
                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseBracket) {
                        return Err(ParseError {
                            message: "Missing ']'".to_string(),
                            span: self.current_span(),
                        });
                    }
                    Ok(Expr::IndirectLong(
                        Box::new(expr),
                        Span {
                            line: open_span.line,
                            col_start: open_span.col_start,
                            col_end: close_span.col_end,
                        },
                    ))
                }
            }
            Some(Token {
                kind: TokenKind::OpenBrace,
                span: open_span,
            }) => {
                let mut elements = Vec::new();
                if !self.consume_kind(TokenKind::CloseBrace) {
                    elements.push(self.parse_expr()?);
                    while self.consume_comma() {
                        elements.push(self.parse_expr()?);
                    }
                    if !self.consume_kind(TokenKind::CloseBrace) {
                        return Err(ParseError {
                            message: "Missing '}' in list literal".to_string(),
                            span: self.current_span(),
                        });
                    }
                }
                let close_span = self.prev_span();
                Ok(Expr::List(
                    elements,
                    Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    },
                ))
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
        }?;

        let base = self.parse_struct_literal_if_present(base)?;
        self.parse_postfix_expr(base)
    }

    fn parse_struct_literal_if_present(&mut self, expr: Expr) -> Result<Expr, ParseError> {
        let (type_name, type_span) = match &expr {
            Expr::Identifier(name, span) | Expr::Register(name, span) => (name.clone(), *span),
            _ => return Ok(expr),
        };
        if !self.peek_kind(TokenKind::OpenBrace) {
            return Ok(expr);
        }
        self.index += 1; // '{'

        let mut fields = Vec::new();
        if !self.consume_kind(TokenKind::CloseBrace) {
            loop {
                let field_name = match self.next() {
                    Some(Token {
                        kind: TokenKind::Identifier(name),
                        ..
                    })
                    | Some(Token {
                        kind: TokenKind::Register(name),
                        ..
                    }) => name,
                    Some(token) => {
                        return Err(ParseError {
                            message: "Expected field name in struct literal".to_string(),
                            span: token.span,
                        })
                    }
                    None => {
                        return Err(ParseError {
                            message: "Expected field name in struct literal".to_string(),
                            span: self.end_span,
                        })
                    }
                };

                if !self.consume_kind(TokenKind::Colon) {
                    return Err(ParseError {
                        message: "Expected ':' after field name in struct literal".to_string(),
                        span: self.current_span(),
                    });
                }
                let field_expr = self.parse_expr()?;
                fields.push((field_name, field_expr));

                if self.consume_comma() {
                    continue;
                }
                if !self.consume_kind(TokenKind::CloseBrace) {
                    return Err(ParseError {
                        message: "Missing '}' in struct literal".to_string(),
                        span: self.current_span(),
                    });
                }
                break;
            }
        }

        let close_span = self.prev_span();
        Ok(Expr::StructLiteral {
            type_name,
            fields,
            span: Span {
                line: type_span.line,
                col_start: type_span.col_start,
                col_end: close_span.col_end,
            },
        })
    }

    fn parse_postfix_expr(&mut self, mut expr: Expr) -> Result<Expr, ParseError> {
        loop {
            if self.consume_kind(TokenKind::OpenBracket) {
                let index = self.parse_expr()?;
                let close_span = self.current_span();
                if !self.consume_kind(TokenKind::CloseBracket) {
                    return Err(ParseError {
                        message: "Missing ']' in index expression".to_string(),
                        span: self.current_span(),
                    });
                }
                let start_span = span_of_expr(&expr);
                expr = Expr::Index {
                    base: Box::new(expr),
                    index: Box::new(index),
                    span: Span {
                        line: start_span.line,
                        col_start: start_span.col_start,
                        col_end: close_span.col_end,
                    },
                };
                continue;
            }

            if self.consume_kind(TokenKind::Dot) {
                let (field, field_span) = match self.next() {
                    Some(Token {
                        kind: TokenKind::Identifier(name),
                        span,
                    })
                    | Some(Token {
                        kind: TokenKind::Register(name),
                        span,
                    }) => (name, span),
                    Some(token) => {
                        return Err(ParseError {
                            message: "Expected member name after '.'".to_string(),
                            span: token.span,
                        })
                    }
                    None => {
                        return Err(ParseError {
                            message: "Expected member name after '.'".to_string(),
                            span: self.end_span,
                        })
                    }
                };
                let start_span = span_of_expr(&expr);
                expr = Expr::Member {
                    base: Box::new(expr),
                    field,
                    span: Span {
                        line: start_span.line,
                        col_start: start_span.col_start,
                        col_end: field_span.col_end,
                    },
                };
                continue;
            }

            break;
        }
        Ok(expr)
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

    fn peek_kind(&self, kind: TokenKind) -> bool {
        self.peek().is_some_and(|token| token.kind == kind)
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
            .map(|token| token.span)
            .unwrap_or(self.end_span)
    }
}

fn span_of_expr(expr: &Expr) -> Span {
    match expr {
        Expr::Number(_, span)
        | Expr::Identifier(_, span)
        | Expr::Register(_, span)
        | Expr::List(_, span)
        | Expr::Index { span, .. }
        | Expr::Member { span, .. }
        | Expr::StructLiteral { span, .. }
        | Expr::Call { span, .. }
        | Expr::Placeholder(span)
        | Expr::Indirect(_, span)
        | Expr::Immediate(_, span)
        | Expr::IndirectLong(_, span)
        | Expr::Tuple(_, span)
        | Expr::Dollar(span)
        | Expr::String(_, span)
        | Expr::Error(_, span)
        | Expr::Range { span, .. } => *span,
        Expr::Ternary { span, .. } | Expr::Unary { span, .. } | Expr::Binary { span, .. } => *span,
    }
}
