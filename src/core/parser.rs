// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Parser for tokenized assembly source.

use crate::core::text_utils::is_ident_start;
use crate::core::tokenizer::{
    ConditionalKind, OperatorKind, Span, Token, TokenKind, TokenizeError, Tokenizer,
};

#[path = "parser_statement_signature.rs"]
mod parser_statement_signature;
pub use parser_statement_signature::{match_statement_signature, select_statement_signature};

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
    Place {
        section: String,
        region: String,
        align: Option<Expr>,
        span: Span,
    },
    Pack {
        region: String,
        sections: Vec<String>,
        span: Span,
    },
    Use {
        module_id: String,
        alias: Option<String>,
        items: Vec<UseItem>,
        params: Vec<UseParam>,
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
    List(Vec<Expr>, Span),
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    Member {
        base: Box<Expr>,
        field: String,
        span: Span,
    },
    Call {
        name: String,
        args: Vec<Expr>,
        span: Span,
    },
    Placeholder(Span),
    /// Indirect/memory reference via register: (HL), (BC), (IX+d), etc.
    /// For simple cases like (HL), the inner is Register.
    /// For indexed like (IX+5), the inner is Binary with base register.
    Indirect(Box<Expr>, Span),
    /// Immediate value: #expr
    Immediate(Box<Expr>, Span),
    /// Bracketed long-indirect expression: [expr]
    IndirectLong(Box<Expr>, Span),
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
    Range {
        start: Box<Expr>,
        end: Box<Expr>,
        step: Option<Box<Expr>>,
        inclusive: bool,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct UseItem {
    pub name: String,
    pub alias: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UseParam {
    pub name: String,
    pub value: Expr,
    pub span: Span,
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

/// Maximum nesting depth for recursive expression parsing (unary chains,
/// parenthesised sub-expressions). Prevents stack overflow on malicious or
/// pathological input.
const MAX_PARSE_DEPTH: usize = 256;

pub struct Parser {
    tokens: Vec<Token>,
    index: usize,
    end_span: Span,
    end_token_text: Option<String>,
    parse_depth: usize,
}

impl Parser {
    fn from_token_parts(
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Self {
        Self {
            tokens,
            index: 0,
            end_span,
            end_token_text,
            parse_depth: 0,
        }
    }
    pub fn from_line(line: &str, line_num: u32) -> Result<Self, ParseError> {
        Self::from_line_with_registers(
            line,
            line_num,
            crate::core::tokenizer::register_checker_none(),
        )
    }

    pub fn from_tokens(tokens: Vec<Token>, end_span: Span, end_token_text: Option<String>) -> Self {
        Self::from_token_parts(tokens, end_span, end_token_text)
    }

    pub fn parse_line_from_tokens(
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Result<LineAst, ParseError> {
        let mut parser = Self::from_token_parts(tokens, end_span, end_token_text);
        parser.parse_line()
    }

    pub fn parse_expr_from_tokens(
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Result<Expr, ParseError> {
        let mut parser = Self::from_token_parts(tokens, end_span, end_token_text);
        let expr = parser.parse_expr()?;
        if parser.index < parser.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: parser.tokens[parser.index].span,
            });
        }
        Ok(expr)
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
        Ok(Self::from_token_parts(tokens, end_span, end_token_text))
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
            if upper.as_str() == "USE" {
                return self.parse_use_directive(span);
            }
            if upper.as_str() == "PLACE" {
                return self.parse_place_directive(span);
            }
            if upper.as_str() == "PACK" {
                return self.parse_pack_directive(span);
            }
            if matches!(upper.as_str(), "FOR" | "BFOR") {
                return self.parse_for_like_directive(label, name);
            }
            if matches!(upper.as_str(), "WHILE" | "BWHILE") {
                return self.parse_while_like_directive(label, name);
            }
            if matches!(
                upper.as_str(),
                "STRUCT" | "ENDSTRUCT" | "ENDFOR" | "ENDWHILE"
            ) {
                if self.index < self.tokens.len() {
                    return Err(ParseError {
                        message: "Unexpected trailing tokens".to_string(),
                        span: self.tokens[self.index].span,
                    });
                }
                return Ok(LineAst::Statement {
                    label,
                    mnemonic: Some(format!(".{name}")),
                    operands: Vec::new(),
                });
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
            if self.consume_comma() {
                let comma_span = self.prev_span();
                operands.push(Expr::Number("0".to_string(), comma_span));
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
            } else {
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

    fn parse_place_directive(&mut self, start_span: Span) -> Result<LineAst, ParseError> {
        let (section, section_span) = self.parse_ident_like("Expected section name for .place")?;
        let (in_kw, in_span) = self.parse_ident_like("Expected 'in' in .place directive")?;
        if !in_kw.eq_ignore_ascii_case("in") {
            return Err(ParseError {
                message: "Expected 'in' in .place directive".to_string(),
                span: in_span,
            });
        }
        let (region, _) = self.parse_ident_like("Expected region name for .place")?;

        let mut align = None;
        if self.consume_comma() {
            let (key, key_span) =
                self.parse_ident_like("Expected option key after ',' in .place directive")?;
            if !key.eq_ignore_ascii_case("align") {
                return Err(ParseError {
                    message: "Unknown .place option key".to_string(),
                    span: key_span,
                });
            }
            if !self.match_operator(OperatorKind::Eq) {
                return Err(ParseError {
                    message: "Expected '=' after align in .place directive".to_string(),
                    span: self.current_span(),
                });
            }
            align = Some(self.parse_expr()?);
        }

        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: self.tokens[self.index].span,
            });
        }

        let end_span = if self.index == 0 {
            section_span
        } else {
            self.prev_span()
        };
        Ok(LineAst::Place {
            section,
            region,
            align,
            span: Span {
                line: start_span.line,
                col_start: start_span.col_start,
                col_end: end_span.col_end,
            },
        })
    }

    fn parse_for_like_directive(
        &mut self,
        label: Option<Label>,
        name: String,
    ) -> Result<LineAst, ParseError> {
        let mut operands = Vec::new();
        let mnemonic = Some(format!(".{name}"));

        let start_index = self.index;
        if let Some(Token {
            kind: TokenKind::Identifier(var_name),
            span: var_span,
        })
        | Some(Token {
            kind: TokenKind::Register(var_name),
            span: var_span,
        }) = self.peek().cloned()
        {
            self.index = self.index.saturating_add(1);
            if self.match_keyword("in") {
                operands.push(Expr::Identifier(var_name, var_span));
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
                if self.index < self.tokens.len() {
                    return Err(ParseError {
                        message: "Unexpected trailing tokens".to_string(),
                        span: self.tokens[self.index].span,
                    });
                }
                return Ok(LineAst::Statement {
                    label,
                    mnemonic,
                    operands,
                });
            }
        }

        self.index = start_index;
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

    fn parse_while_like_directive(
        &mut self,
        label: Option<Label>,
        name: String,
    ) -> Result<LineAst, ParseError> {
        let mut operands = Vec::new();
        let mnemonic = Some(format!(".{name}"));

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

    fn parse_pack_directive(&mut self, start_span: Span) -> Result<LineAst, ParseError> {
        let (in_kw, in_span) = self.parse_ident_like("Expected 'in' in .pack directive")?;
        if !in_kw.eq_ignore_ascii_case("in") {
            return Err(ParseError {
                message: "Expected 'in' in .pack directive".to_string(),
                span: in_span,
            });
        }
        let (region, _) = self.parse_ident_like("Expected region name for .pack")?;
        if !self.consume_kind(TokenKind::Colon) {
            return Err(ParseError {
                message: "Expected ':' in .pack directive".to_string(),
                span: self.current_span(),
            });
        }

        let mut sections = Vec::new();
        let (first_section, _) =
            self.parse_ident_like("Expected at least one section in .pack directive")?;
        sections.push(first_section);
        while self.consume_comma() {
            let (name, _) =
                self.parse_ident_like("Expected section name after ',' in .pack directive")?;
            sections.push(name);
        }

        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: self.tokens[self.index].span,
            });
        }

        let end_span = if self.index == 0 {
            start_span
        } else {
            self.prev_span()
        };
        Ok(LineAst::Pack {
            region,
            sections,
            span: Span {
                line: start_span.line,
                col_start: start_span.col_start,
                col_end: end_span.col_end,
            },
        })
    }

    fn match_assignment_op(&self) -> Option<(AssignOp, Span, usize)> {
        let token = self.tokens.get(self.index)?;
        let next = self.tokens.get(self.index + 1);
        let next2 = self.tokens.get(self.index + 2);
        match &token.kind {
            TokenKind::Operator(OperatorKind::Eq) => Some((AssignOp::Const, token.span, 1)),
            TokenKind::Colon => {
                if matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Question,
                        ..
                    })
                ) && matches!(
                    next2,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
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
                if *kind == OperatorKind::RangeInclusive {
                    return Some((AssignOp::Concat, token.span, 1));
                }
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
                        if matches!(
                            next,
                            Some(Token {
                                kind: TokenKind::Question,
                                ..
                            })
                        ) && matches!(
                            next2,
                            Some(Token {
                                kind: TokenKind::Operator(OperatorKind::Eq),
                                ..
                            })
                        ) {
                            return Some((AssignOp::Min, token.span, 3));
                        }
                        return None;
                    }
                    OperatorKind::Gt => {
                        if matches!(
                            next,
                            Some(Token {
                                kind: TokenKind::Question,
                                ..
                            })
                        ) && matches!(
                            next2,
                            Some(Token {
                                kind: TokenKind::Operator(OperatorKind::Eq),
                                ..
                            })
                        ) {
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
                if matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Dot,
                        ..
                    })
                ) && matches!(
                    next2,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                ) {
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
                    && matches!(
                        next,
                        Some(Token {
                            kind: TokenKind::Operator(OperatorKind::Eq),
                            ..
                        })
                    )
                {
                    Some((AssignOp::Repeat, token.span, 2))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn parse_statement_signature(
        &mut self,
        in_boundary: bool,
    ) -> Result<StatementSignature, ParseError> {
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
                let token = self.expect_next(|| "Missing closing }]".to_string())?;
                return Err(ParseError {
                    message: "Missing closing }]".to_string(),
                    span: token.span,
                });
            }

            if self.peek_kind(TokenKind::OpenBracket) && self.peek_kind_next(TokenKind::OpenBrace) {
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

            let token = self.expect_next(|| "Unexpected end of statement signature".to_string())?;
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
                    if !parser_statement_signature::is_valid_capture_type(&type_name) {
                        return Err(ParseError {
                            message: format!("Unknown statement capture type: {type_name}"),
                            span: token.span,
                        });
                    }
                    let colon =
                        self.expect_next(|| "Expected ':' after capture type".to_string())?;
                    if !matches!(colon.kind, TokenKind::Colon) {
                        return Err(ParseError {
                            message: "Expected ':' after capture type".to_string(),
                            span: colon.span,
                        });
                    }
                    let next =
                        self.expect_next(|| "Expected capture name after type".to_string())?;
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

    fn expect_next<F>(&mut self, message: F) -> Result<Token, ParseError>
    where
        F: FnOnce() -> String,
    {
        self.next().ok_or_else(|| ParseError {
            message: message(),
            span: self.end_span,
        })
    }

    fn peek_kind(&self, kind: TokenKind) -> bool {
        matches!(self.peek(), Some(Token { kind: k, .. }) if *k == kind)
    }

    fn peek_kind_next(&self, kind: TokenKind) -> bool {
        matches!(self.tokens.get(self.index + 1), Some(Token { kind: k, .. }) if *k == kind)
    }

    fn match_keyword(&mut self, keyword: &str) -> bool {
        match self.peek() {
            Some(Token {
                kind: TokenKind::Identifier(name),
                ..
            }) if name.eq_ignore_ascii_case(keyword) => {
                self.index += 1;
                true
            }
            _ => false,
        }
    }

    fn parse_ident_like(&mut self, message: &str) -> Result<(String, Span), ParseError> {
        match self.next() {
            Some(Token {
                kind: TokenKind::Identifier(name),
                span,
            }) => Ok((name, span)),
            Some(Token {
                kind: TokenKind::Register(name),
                span,
            }) => Ok((name, span)),
            Some(token) => Err(ParseError {
                message: message.to_string(),
                span: token.span,
            }),
            None => Err(ParseError {
                message: message.to_string(),
                span: self.end_span,
            }),
        }
    }

    fn parse_use_directive(&mut self, start_span: Span) -> Result<LineAst, ParseError> {
        let (module_id, _module_span) = self.parse_ident_like("Expected module id after .use")?;
        let mut alias = None;
        let mut items = Vec::new();
        let mut params = Vec::new();

        if self.match_keyword("as") {
            let (name, _span) = self.parse_ident_like("Expected alias identifier after 'as'")?;
            alias = Some(name);
        }

        if self.consume_kind(TokenKind::OpenParen) {
            if self.consume_kind(TokenKind::CloseParen) {
                return Err(ParseError {
                    message: "Selective import list cannot be empty".to_string(),
                    span: self.prev_span(),
                });
            }
            if self.match_operator(OperatorKind::Multiply) {
                let star_span = self.prev_span();
                if self.match_keyword("as") {
                    return Err(ParseError {
                        message: "Wildcard import cannot have an alias".to_string(),
                        span: self.current_span(),
                    });
                }
                if !self.consume_kind(TokenKind::CloseParen) {
                    return Err(ParseError {
                        message: "Wildcard import must be the only selective item".to_string(),
                        span: self.current_span(),
                    });
                }
                items.push(UseItem {
                    name: "*".to_string(),
                    alias: None,
                    span: star_span,
                });
            } else {
                loop {
                    let (name, span) =
                        self.parse_ident_like("Expected identifier in selective import list")?;
                    let mut item_alias = None;
                    if self.match_keyword("as") {
                        let (alias_name, _alias_span) =
                            self.parse_ident_like("Expected alias in selective import list")?;
                        item_alias = Some(alias_name);
                    }
                    items.push(UseItem {
                        name,
                        alias: item_alias,
                        span,
                    });
                    if self.consume_kind(TokenKind::CloseParen) {
                        break;
                    }
                    if !self.consume_comma() {
                        return Err(ParseError {
                            message: "Expected ',' or ')' in selective import list".to_string(),
                            span: self.current_span(),
                        });
                    }
                }
            }
        }

        if self.match_keyword("with") {
            if !self.consume_kind(TokenKind::OpenParen) {
                return Err(ParseError {
                    message: "Expected '(' after 'with'".to_string(),
                    span: self.current_span(),
                });
            }
            if self.consume_kind(TokenKind::CloseParen) {
                return Err(ParseError {
                    message: "Parameter list cannot be empty".to_string(),
                    span: self.prev_span(),
                });
            }
            loop {
                let (name, span) =
                    self.parse_ident_like("Expected parameter name in 'with' list")?;
                if !self.match_operator(OperatorKind::Eq) {
                    return Err(ParseError {
                        message: "Expected '=' in 'with' parameter".to_string(),
                        span: self.current_span(),
                    });
                }
                let value = self.parse_expr()?;
                params.push(UseParam { name, value, span });
                if self.consume_kind(TokenKind::CloseParen) {
                    break;
                }
                if !self.consume_comma() {
                    return Err(ParseError {
                        message: "Expected ',' or ')' in 'with' parameter list".to_string(),
                        span: self.current_span(),
                    });
                }
            }
        }

        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens after .use".to_string(),
                span: self.tokens[self.index].span,
            });
        }

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

        Ok(LineAst::Use {
            module_id,
            alias,
            items,
            params,
            span,
        })
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
            self.parse_depth += 1;
            if self.parse_depth > MAX_PARSE_DEPTH {
                let span = self.current_span();
                return Err(ParseError {
                    message: format!(
                        "Expression nesting exceeds maximum depth ({})",
                        MAX_PARSE_DEPTH
                    ),
                    span,
                });
            }
            self.index += 1;
            let span = self.prev_span();
            let expr = self.parse_unary()?;
            self.parse_depth -= 1;
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

        self.parse_postfix_expr(base)
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

fn span_of_expr(expr: &Expr) -> Span {
    match expr {
        Expr::Number(_, span)
        | Expr::Identifier(_, span)
        | Expr::Register(_, span)
        | Expr::List(_, span)
        | Expr::Index { span, .. }
        | Expr::Member { span, .. }
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

#[cfg(test)]
mod tests {
    use super::{
        match_statement_signature, select_statement_signature, AssignOp, BinaryOp, ConditionalKind,
        Expr, LineAst, Parser, SignatureAtom,
    };
    use crate::core::tokenizer::{Span, Tokenizer};

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
    fn parser_from_tokens_preserves_end_metadata() {
        let tokens = tokenize_line("LDA #$42");
        let end_span = Span {
            line: 1,
            col_start: 99,
            col_end: 99,
        };
        let parser = Parser::from_tokens(tokens, end_span, Some(";".to_string()));
        assert_eq!(parser.end_span(), end_span);
        assert_eq!(parser.end_token_text(), Some(";"));
    }

    #[test]
    fn parser_from_tokens_matches_line_parse_for_basic_statement() {
        let line = "LABEL: MOV A,B";
        let tokens = tokenize_line(line);
        let mut from_line = Parser::from_line(line, 1).unwrap();
        let expected = from_line.parse_line().unwrap();
        let mut from_tokens = Parser::from_tokens(
            tokens,
            Span {
                line: 1,
                col_start: line.len() + 1,
                col_end: line.len() + 1,
            },
            None,
        );
        let actual = from_tokens.parse_line().unwrap();
        assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
    }

    #[test]
    fn parses_label_and_mnemonic() {
        let mut parser = Parser::from_line("LABEL: MOV A,B", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
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
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
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
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
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
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".byte"));
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_place_directive() {
        let mut parser = Parser::from_line(".place code in ram, align=2", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Place {
                section,
                region,
                align,
                ..
            } => {
                assert_eq!(section, "code");
                assert_eq!(region, "ram");
                assert!(align.is_some());
            }
            _ => panic!("Expected place directive"),
        }
    }

    #[test]
    fn parses_pack_directive() {
        let mut parser = Parser::from_line(".pack in ram : code, data", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Pack {
                region, sections, ..
            } => {
                assert_eq!(region, "ram");
                assert_eq!(sections, vec!["code".to_string(), "data".to_string()]);
            }
            _ => panic!("Expected pack directive"),
        }
    }

    #[test]
    fn parses_use_basic() {
        let mut parser = Parser::from_line(".use std.math", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Use {
                module_id,
                alias,
                items,
                params,
                ..
            } => {
                assert_eq!(module_id, "std.math");
                assert!(alias.is_none());
                assert!(items.is_empty());
                assert!(params.is_empty());
            }
            _ => panic!("Expected use directive"),
        }
    }

    #[test]
    fn parses_use_with_alias_selective_params() {
        let mut parser = Parser::from_line(
            ".use std.math as M (add16, sub16 as sub) with (FEATURE=1)",
            1,
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Use {
                module_id,
                alias,
                items,
                params,
                ..
            } => {
                assert_eq!(module_id, "std.math");
                assert_eq!(alias.as_deref(), Some("M"));
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].name, "add16");
                assert_eq!(items[1].alias.as_deref(), Some("sub"));
                assert_eq!(params.len(), 1);
                assert_eq!(params[0].name, "FEATURE");
            }
            _ => panic!("Expected use directive"),
        }
    }

    #[test]
    fn rejects_empty_selective_list() {
        let mut parser = Parser::from_line(".use std.math ()", 1).unwrap();
        assert!(parser.parse_line().is_err());
    }

    #[test]
    fn parses_use_wildcard_selective_list() {
        let mut parser = Parser::from_line(".use std.math (*)", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Use { items, .. } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].name, "*");
                assert!(items[0].alias.is_none());
            }
            _ => panic!("Expected use directive"),
        }
    }

    #[test]
    fn rejects_wildcard_with_alias_in_selective_list() {
        let mut parser = Parser::from_line(".use std.math (* as all)", 1).unwrap();
        assert!(parser.parse_line().is_err());
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
            LineAst::Statement {
                label, mnemonic, ..
            } => {
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
        let mut parser = Parser::from_line(".statement move.b char:dst \",\" char:src", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::StatementDef {
                keyword, signature, ..
            } => {
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
        let mut parser =
            Parser::from_line(".statement sta \"[\" byte:a \",\"[{char:reg}]", 1).unwrap();
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
        let mut sig_parser = Parser::from_line(".statement sta \"],y\"", 1).unwrap();
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
        let mut parser1 = Parser::from_line(".statement foo \"x\" byte:a", 1).unwrap();
        let sig1 = match parser1.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };
        assert_eq!(sig1.atoms.len(), 2);
        assert!(matches!(sig1.atoms[0], SignatureAtom::Literal(_, _)));
        assert!(matches!(sig1.atoms[1], SignatureAtom::Capture { .. }));

        let mut parser2 = Parser::from_line(".statement foo byte:a", 1).unwrap();
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
        let mut parser = Parser::from_line(".statement foo byte:a", 1).unwrap();
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
        let mut parser = Parser::from_line(".statement foo word:a", 1).unwrap();
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
        let mut parser = Parser::from_line(".statement foo char:c", 1).unwrap();
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
        let mut parser = Parser::from_line(".statement foo str:s", 1).unwrap();
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
        let mut parser = Parser::from_line(".statement move reg:dst", 1).unwrap();
        let err = parser.parse_line().expect_err("expected error");
        assert!(err.message.contains("Unknown statement capture type"));
    }

    #[test]
    fn statement_signature_rejects_unquoted_commas() {
        let mut parser = Parser::from_line(".statement move.b char:dst, char:src", 1).unwrap();
        let err = parser.parse_line().expect_err("expected error");
        assert!(err
            .message
            .contains("Commas must be quoted in statement signatures"));
    }

    #[test]
    fn statement_signature_selection_reports_ambiguity() {
        let mut parser1 = Parser::from_line(".statement foo byte:a", 1).unwrap();
        let sig1 = match parser1.parse_line().unwrap() {
            LineAst::StatementDef { signature, .. } => signature,
            _ => panic!("Expected statement definition"),
        };

        let mut parser2 = Parser::from_line(".statement foo word:b", 1).unwrap();
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
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".org"));
                assert_eq!(operands.len(), 1);
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_range_expression() {
        let expr = Parser::parse_expr_from_tokens(
            tokenize_line("0..8"),
            Span {
                line: 1,
                col_start: 5,
                col_end: 5,
            },
            None,
        )
        .expect("range expression should parse");

        match expr {
            Expr::Range {
                inclusive,
                step,
                start,
                end,
                ..
            } => {
                assert!(!inclusive);
                assert!(step.is_none());
                assert!(matches!(*start, Expr::Number(_, _)));
                assert!(matches!(*end, Expr::Number(_, _)));
            }
            other => panic!("Expected range expression, got {other:?}"),
        }
    }

    #[test]
    fn parses_inclusive_range_with_step_expression() {
        let expr = Parser::parse_expr_from_tokens(
            tokenize_line("10..=0:-1"),
            Span {
                line: 1,
                col_start: 10,
                col_end: 10,
            },
            None,
        )
        .expect("inclusive range with step should parse");

        match expr {
            Expr::Range {
                inclusive,
                step,
                start,
                end,
                ..
            } => {
                assert!(inclusive);
                assert!(step.is_some());
                assert!(matches!(*start, Expr::Number(_, _)));
                assert!(matches!(*end, Expr::Number(_, _)));
            }
            other => panic!("Expected range expression, got {other:?}"),
        }
    }

    #[test]
    fn parses_list_literal_expression() {
        let expr = Parser::parse_expr_from_tokens(
            tokenize_line("{1,2,3}"),
            Span {
                line: 1,
                col_start: 8,
                col_end: 8,
            },
            None,
        )
        .expect("list expression should parse");

        match expr {
            Expr::List(items, _) => {
                assert_eq!(items.len(), 3);
                assert!(items.iter().all(|item| matches!(item, Expr::Number(_, _))));
            }
            other => panic!("Expected list expression, got {other:?}"),
        }
    }

    #[test]
    fn parses_index_then_member_expression() {
        let expr = Parser::parse_expr_from_tokens(
            tokenize_line("arr[2].len"),
            Span {
                line: 1,
                col_start: 11,
                col_end: 11,
            },
            None,
        )
        .expect("postfix expression should parse");

        match expr {
            Expr::Member { base, field, .. } => {
                assert_eq!(field, "len");
                assert!(matches!(*base, Expr::Index { .. }));
            }
            other => panic!("Expected member expression, got {other:?}"),
        }
    }

    #[test]
    fn parses_dot_call_with_placeholder_argument() {
        let expr = Parser::parse_expr_from_tokens(
            tokenize_line(".pick({1,2},?)"),
            Span {
                line: 1,
                col_start: 14,
                col_end: 14,
            },
            None,
        )
        .expect("call expression should parse");

        match expr {
            Expr::Call { name, args, .. } => {
                assert_eq!(name, ".pick");
                assert_eq!(args.len(), 2);
                assert!(matches!(args[0], Expr::List(_, _)));
                assert!(matches!(args[1], Expr::Placeholder(_)));
            }
            other => panic!("Expected call expression, got {other:?}"),
        }
    }

    #[test]
    fn parses_for_directive_var_in_head() {
        let mut parser = Parser::from_line(".for i in 0..8", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".for"));
                assert_eq!(operands.len(), 2);
                assert!(matches!(operands[0], Expr::Identifier(ref name, _) if name == "i"));
                assert!(matches!(operands[1], Expr::Range { .. }));
            }
            other => panic!("Expected .for statement, got {other:?}"),
        }
    }

    #[test]
    fn parses_for_directive_count_head() {
        let mut parser = Parser::from_line(".for 4+1", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".for"));
                assert_eq!(operands.len(), 1);
                assert!(matches!(operands[0], Expr::Binary { .. }));
            }
            other => panic!("Expected .for statement, got {other:?}"),
        }
    }

    #[test]
    fn parses_while_directive_head() {
        let mut parser = Parser::from_line(".while addr < $c100", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".while"));
                assert_eq!(operands.len(), 1);
                assert!(matches!(
                    operands[0],
                    Expr::Binary {
                        op: BinaryOp::Lt,
                        ..
                    }
                ));
            }
            other => panic!("Expected .while statement, got {other:?}"),
        }
    }

    #[test]
    fn parses_endfor_without_operands() {
        let mut parser = Parser::from_line(".endfor", 1).unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some(".endfor"));
                assert!(operands.is_empty());
            }
            other => panic!("Expected .endfor statement, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_tokens_after_endfor() {
        let mut parser = Parser::from_line(".endfor 1", 1).unwrap();
        let err = parser
            .parse_line()
            .expect_err("trailing tokens after .endfor should fail");
        assert!(err.message.contains("Unexpected trailing tokens"));
    }
}
