use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortableSpan {
    pub line: u32,
    pub col_start: usize,
    pub col_end: usize,
}

impl From<Span> for PortableSpan {
    fn from(value: Span) -> Self {
        Self {
            line: value.line,
            col_start: value.col_start,
            col_end: value.col_end,
        }
    }
}

impl From<PortableSpan> for Span {
    fn from(value: PortableSpan) -> Self {
        Self {
            line: value.line,
            col_start: value.col_start,
            col_end: value.col_end,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableOperatorKind {
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

macro_rules! impl_enum_mirror_froms {
    ($left:ty, $right:ty, { $($variant:ident),+ $(,)? }) => {
        impl From<$left> for $right {
            fn from(value: $left) -> Self {
                match value {
                    $(<$left>::$variant => <$right>::$variant,)+
                }
            }
        }

        impl From<$right> for $left {
            fn from(value: $right) -> Self {
                match value {
                    $(<$right>::$variant => <$left>::$variant,)+
                }
            }
        }
    };
}

impl_enum_mirror_froms!(OperatorKind, PortableOperatorKind, {
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
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableTokenKind {
    Identifier(String),
    Register(String),
    Number { text: String, base: u32 },
    String { raw: String, bytes: Vec<u8> },
    Comma,
    Colon,
    Dollar,
    Dot,
    Hash,
    Question,
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,
    OpenParen,
    CloseParen,
    Operator(PortableOperatorKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableToken {
    pub kind: PortableTokenKind,
    pub span: PortableSpan,
}

impl PortableToken {
    pub(crate) fn from_core_token(value: Token) -> Option<Self> {
        let kind = match value.kind {
            TokenKind::Identifier(name) => PortableTokenKind::Identifier(name),
            TokenKind::Register(name) => PortableTokenKind::Register(name),
            TokenKind::Number(NumberLiteral { text, base }) => {
                PortableTokenKind::Number { text, base }
            }
            TokenKind::String(StringLiteral { raw, bytes }) => {
                PortableTokenKind::String { raw, bytes }
            }
            TokenKind::Comma => PortableTokenKind::Comma,
            TokenKind::Colon => PortableTokenKind::Colon,
            TokenKind::Dollar => PortableTokenKind::Dollar,
            TokenKind::Dot => PortableTokenKind::Dot,
            TokenKind::Hash => PortableTokenKind::Hash,
            TokenKind::Question => PortableTokenKind::Question,
            TokenKind::OpenBracket => PortableTokenKind::OpenBracket,
            TokenKind::CloseBracket => PortableTokenKind::CloseBracket,
            TokenKind::OpenBrace => PortableTokenKind::OpenBrace,
            TokenKind::CloseBrace => PortableTokenKind::CloseBrace,
            TokenKind::OpenParen => PortableTokenKind::OpenParen,
            TokenKind::CloseParen => PortableTokenKind::CloseParen,
            TokenKind::Operator(op) => PortableTokenKind::Operator(op.into()),
            TokenKind::End => return None,
        };
        Some(Self {
            kind,
            span: value.span.into(),
        })
    }

    pub(crate) fn to_core_token(&self) -> Token {
        let kind = match &self.kind {
            PortableTokenKind::Identifier(name) => TokenKind::Identifier(name.clone()),
            PortableTokenKind::Register(name) => TokenKind::Register(name.clone()),
            PortableTokenKind::Number { text, base } => TokenKind::Number(NumberLiteral {
                text: text.clone(),
                base: *base,
            }),
            PortableTokenKind::String { raw, bytes } => TokenKind::String(StringLiteral {
                raw: raw.clone(),
                bytes: bytes.clone(),
            }),
            PortableTokenKind::Comma => TokenKind::Comma,
            PortableTokenKind::Colon => TokenKind::Colon,
            PortableTokenKind::Dollar => TokenKind::Dollar,
            PortableTokenKind::Dot => TokenKind::Dot,
            PortableTokenKind::Hash => TokenKind::Hash,
            PortableTokenKind::Question => TokenKind::Question,
            PortableTokenKind::OpenBracket => TokenKind::OpenBracket,
            PortableTokenKind::CloseBracket => TokenKind::CloseBracket,
            PortableTokenKind::OpenBrace => TokenKind::OpenBrace,
            PortableTokenKind::CloseBrace => TokenKind::CloseBrace,
            PortableTokenKind::OpenParen => TokenKind::OpenParen,
            PortableTokenKind::CloseParen => TokenKind::CloseParen,
            PortableTokenKind::Operator(op) => TokenKind::Operator((*op).into()),
        };
        Token {
            kind,
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstLabel {
    pub name: String,
    pub span: PortableSpan,
}

impl PortableAstLabel {
    pub(crate) fn from_core_label(label: &Label) -> Self {
        Self {
            name: label.name.clone(),
            span: label.span.into(),
        }
    }

    pub(crate) fn to_core_label(&self) -> Label {
        Label {
            name: self.name.clone(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableAstUnaryOp {
    Plus,
    Minus,
    BitNot,
    LogicNot,
    High,
    Low,
}

impl_enum_mirror_froms!(UnaryOp, PortableAstUnaryOp, {
    Plus,
    Minus,
    BitNot,
    LogicNot,
    High,
    Low,
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableAstBinaryOp {
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

impl_enum_mirror_froms!(BinaryOp, PortableAstBinaryOp, {
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
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableAstExpr {
    Number(String, PortableSpan),
    Identifier(String, PortableSpan),
    Register(String, PortableSpan),
    Indirect(Box<PortableAstExpr>, PortableSpan),
    Dollar(PortableSpan),
    String(Vec<u8>, PortableSpan),
    Immediate(Box<PortableAstExpr>, PortableSpan),
    IndirectLong(Box<PortableAstExpr>, PortableSpan),
    Tuple(Vec<PortableAstExpr>, PortableSpan),
    Error(String, PortableSpan),
    Ternary {
        cond: Box<PortableAstExpr>,
        then_expr: Box<PortableAstExpr>,
        else_expr: Box<PortableAstExpr>,
        span: PortableSpan,
    },
    Unary {
        op: PortableAstUnaryOp,
        expr: Box<PortableAstExpr>,
        span: PortableSpan,
    },
    Binary {
        op: PortableAstBinaryOp,
        left: Box<PortableAstExpr>,
        right: Box<PortableAstExpr>,
        span: PortableSpan,
    },
}

impl PortableAstExpr {
    pub(crate) fn to_core_expr(&self) -> Expr {
        match self {
            Self::Number(text, span) => Expr::Number(text.clone(), (*span).into()),
            Self::Identifier(name, span) => Expr::Identifier(name.clone(), (*span).into()),
            Self::Register(name, span) => Expr::Register(name.clone(), (*span).into()),
            Self::Indirect(inner, span) => {
                Expr::Indirect(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::Dollar(span) => Expr::Dollar((*span).into()),
            Self::String(bytes, span) => Expr::String(bytes.clone(), (*span).into()),
            Self::Immediate(inner, span) => {
                Expr::Immediate(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::IndirectLong(inner, span) => {
                Expr::IndirectLong(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::Tuple(items, span) => Expr::Tuple(
                items.iter().map(PortableAstExpr::to_core_expr).collect(),
                (*span).into(),
            ),
            Self::Error(message, span) => Expr::Error(message.clone(), (*span).into()),
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
                span,
            } => Expr::Ternary {
                cond: Box::new(cond.to_core_expr()),
                then_expr: Box::new(then_expr.to_core_expr()),
                else_expr: Box::new(else_expr.to_core_expr()),
                span: (*span).into(),
            },
            Self::Unary { op, expr, span } => Expr::Unary {
                op: (*op).into(),
                expr: Box::new(expr.to_core_expr()),
                span: (*span).into(),
            },
            Self::Binary {
                op,
                left,
                right,
                span,
            } => Expr::Binary {
                op: (*op).into(),
                left: Box::new(left.to_core_expr()),
                right: Box::new(right.to_core_expr()),
                span: (*span).into(),
            },
        }
    }

    pub(crate) fn from_core_expr(value: &Expr) -> Self {
        match value {
            Expr::Number(text, span) => Self::Number(text.clone(), (*span).into()),
            Expr::Identifier(name, span) => Self::Identifier(name.clone(), (*span).into()),
            Expr::Register(name, span) => Self::Register(name.clone(), (*span).into()),
            Expr::Indirect(inner, span) => {
                Self::Indirect(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::Immediate(inner, span) => {
                Self::Immediate(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::IndirectLong(inner, span) => {
                Self::IndirectLong(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::Tuple(items, span) => Self::Tuple(
                items.iter().map(Self::from_core_expr).collect(),
                (*span).into(),
            ),
            Expr::Dollar(span) => Self::Dollar((*span).into()),
            Expr::String(bytes, span) => Self::String(bytes.clone(), (*span).into()),
            Expr::Error(message, span) => Self::Error(message.clone(), (*span).into()),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                span,
            } => Self::Ternary {
                cond: Box::new(Self::from_core_expr(cond)),
                then_expr: Box::new(Self::from_core_expr(then_expr)),
                else_expr: Box::new(Self::from_core_expr(else_expr)),
                span: (*span).into(),
            },
            Expr::Unary { op, expr, span } => Self::Unary {
                op: (*op).into(),
                expr: Box::new(Self::from_core_expr(expr)),
                span: (*span).into(),
            },
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => Self::Binary {
                op: (*op).into(),
                left: Box::new(Self::from_core_expr(left)),
                right: Box::new(Self::from_core_expr(right)),
                span: (*span).into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstUseItem {
    pub name: String,
    pub alias: Option<String>,
    pub span: PortableSpan,
}

impl PortableAstUseItem {
    pub(crate) fn from_core_item(item: &UseItem) -> Self {
        Self {
            name: item.name.clone(),
            alias: item.alias.clone(),
            span: item.span.into(),
        }
    }

    pub(crate) fn to_core_item(&self) -> UseItem {
        UseItem {
            name: self.name.clone(),
            alias: self.alias.clone(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstUseParam {
    pub name: String,
    pub value: PortableAstExpr,
    pub span: PortableSpan,
}

impl PortableAstUseParam {
    pub(crate) fn from_core_param(param: &UseParam) -> Self {
        Self {
            name: param.name.clone(),
            value: PortableAstExpr::from_core_expr(&param.value),
            span: param.span.into(),
        }
    }

    pub(crate) fn to_core_param(&self) -> UseParam {
        UseParam {
            name: self.name.clone(),
            value: self.value.to_core_expr(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableAstSignatureAtom {
    Literal(Vec<u8>, PortableSpan),
    Capture {
        type_name: String,
        name: String,
        span: PortableSpan,
    },
    Boundary {
        atoms: Vec<PortableAstSignatureAtom>,
        span: PortableSpan,
    },
}

impl PortableAstSignatureAtom {
    pub(crate) fn from_core_atom(atom: &SignatureAtom) -> Self {
        match atom {
            SignatureAtom::Literal(bytes, span) => Self::Literal(bytes.clone(), (*span).into()),
            SignatureAtom::Capture {
                type_name,
                name,
                span,
            } => Self::Capture {
                type_name: type_name.clone(),
                name: name.clone(),
                span: (*span).into(),
            },
            SignatureAtom::Boundary { atoms, span } => Self::Boundary {
                atoms: atoms.iter().map(Self::from_core_atom).collect(),
                span: (*span).into(),
            },
        }
    }

    pub(crate) fn to_core_atom(&self) -> SignatureAtom {
        match self {
            Self::Literal(bytes, span) => SignatureAtom::Literal(bytes.clone(), (*span).into()),
            Self::Capture {
                type_name,
                name,
                span,
            } => SignatureAtom::Capture {
                type_name: type_name.clone(),
                name: name.clone(),
                span: (*span).into(),
            },
            Self::Boundary { atoms, span } => SignatureAtom::Boundary {
                atoms: atoms
                    .iter()
                    .map(PortableAstSignatureAtom::to_core_atom)
                    .collect(),
                span: (*span).into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstStatementSignature {
    pub atoms: Vec<PortableAstSignatureAtom>,
}

impl PortableAstStatementSignature {
    pub(crate) fn from_core_signature(signature: &StatementSignature) -> Self {
        Self {
            atoms: signature
                .atoms
                .iter()
                .map(PortableAstSignatureAtom::from_core_atom)
                .collect(),
        }
    }

    pub(crate) fn to_core_signature(&self) -> StatementSignature {
        StatementSignature {
            atoms: self
                .atoms
                .iter()
                .map(PortableAstSignatureAtom::to_core_atom)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableLineAst {
    Empty,
    Conditional {
        kind: ConditionalKind,
        exprs: Vec<PortableAstExpr>,
        span: PortableSpan,
    },
    Place {
        section: String,
        region: String,
        align: Option<PortableAstExpr>,
        span: PortableSpan,
    },
    Pack {
        region: String,
        sections: Vec<String>,
        span: PortableSpan,
    },
    Use {
        module_id: String,
        alias: Option<String>,
        items: Vec<PortableAstUseItem>,
        params: Vec<PortableAstUseParam>,
        span: PortableSpan,
    },
    StatementDef {
        keyword: String,
        signature: PortableAstStatementSignature,
        span: PortableSpan,
    },
    StatementEnd {
        span: PortableSpan,
    },
    Assignment {
        label: PortableAstLabel,
        op: AssignOp,
        expr: PortableAstExpr,
        span: PortableSpan,
    },
    Statement {
        label: Option<PortableAstLabel>,
        mnemonic: Option<String>,
        operands: Vec<PortableAstExpr>,
    },
}

impl PortableLineAst {
    pub fn from_core_line_ast(value: &LineAst) -> Self {
        match value {
            LineAst::Empty => Self::Empty,
            LineAst::Conditional { kind, exprs, span } => Self::Conditional {
                kind: *kind,
                exprs: exprs.iter().map(PortableAstExpr::from_core_expr).collect(),
                span: (*span).into(),
            },
            LineAst::Place {
                section,
                region,
                align,
                span,
            } => Self::Place {
                section: section.clone(),
                region: region.clone(),
                align: align.as_ref().map(PortableAstExpr::from_core_expr),
                span: (*span).into(),
            },
            LineAst::Pack {
                region,
                sections,
                span,
            } => Self::Pack {
                region: region.clone(),
                sections: sections.clone(),
                span: (*span).into(),
            },
            LineAst::Use {
                module_id,
                alias,
                items,
                params,
                span,
            } => Self::Use {
                module_id: module_id.clone(),
                alias: alias.clone(),
                items: items
                    .iter()
                    .map(PortableAstUseItem::from_core_item)
                    .collect(),
                params: params
                    .iter()
                    .map(PortableAstUseParam::from_core_param)
                    .collect(),
                span: (*span).into(),
            },
            LineAst::StatementDef {
                keyword,
                signature,
                span,
            } => Self::StatementDef {
                keyword: keyword.clone(),
                signature: PortableAstStatementSignature::from_core_signature(signature),
                span: (*span).into(),
            },
            LineAst::StatementEnd { span } => Self::StatementEnd {
                span: (*span).into(),
            },
            LineAst::Assignment {
                label,
                op,
                expr,
                span,
            } => Self::Assignment {
                label: PortableAstLabel::from_core_label(label),
                op: *op,
                expr: PortableAstExpr::from_core_expr(expr),
                span: (*span).into(),
            },
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => Self::Statement {
                label: label.as_ref().map(PortableAstLabel::from_core_label),
                mnemonic: mnemonic.clone(),
                operands: operands
                    .iter()
                    .map(PortableAstExpr::from_core_expr)
                    .collect(),
            },
        }
    }

    pub fn to_core_line_ast(&self) -> LineAst {
        match self {
            Self::Empty => LineAst::Empty,
            Self::Conditional { kind, exprs, span } => LineAst::Conditional {
                kind: *kind,
                exprs: exprs.iter().map(PortableAstExpr::to_core_expr).collect(),
                span: (*span).into(),
            },
            Self::Place {
                section,
                region,
                align,
                span,
            } => LineAst::Place {
                section: section.clone(),
                region: region.clone(),
                align: align.as_ref().map(PortableAstExpr::to_core_expr),
                span: (*span).into(),
            },
            Self::Pack {
                region,
                sections,
                span,
            } => LineAst::Pack {
                region: region.clone(),
                sections: sections.clone(),
                span: (*span).into(),
            },
            Self::Use {
                module_id,
                alias,
                items,
                params,
                span,
            } => LineAst::Use {
                module_id: module_id.clone(),
                alias: alias.clone(),
                items: items.iter().map(PortableAstUseItem::to_core_item).collect(),
                params: params
                    .iter()
                    .map(PortableAstUseParam::to_core_param)
                    .collect(),
                span: (*span).into(),
            },
            Self::StatementDef {
                keyword,
                signature,
                span,
            } => LineAst::StatementDef {
                keyword: keyword.clone(),
                signature: signature.to_core_signature(),
                span: (*span).into(),
            },
            Self::StatementEnd { span } => LineAst::StatementEnd {
                span: (*span).into(),
            },
            Self::Assignment {
                label,
                op,
                expr,
                span,
            } => LineAst::Assignment {
                label: label.to_core_label(),
                op: *op,
                expr: expr.to_core_expr(),
                span: (*span).into(),
            },
            Self::Statement {
                label,
                mnemonic,
                operands,
            } => LineAst::Statement {
                label: label.as_ref().map(PortableAstLabel::to_core_label),
                mnemonic: mnemonic.clone(),
                operands: operands.iter().map(PortableAstExpr::to_core_expr).collect(),
            },
        }
    }
}
