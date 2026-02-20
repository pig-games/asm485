// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::HashMap;

use crate::core::expr::{apply_binary, apply_unary, parse_number};
use crate::core::parser::{BinaryOp, Expr, UnaryOp};
use crate::core::tokenizer::Span;

pub const EXPR_VM_OPCODE_VERSION_V1: u16 = 0x0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExprVmOpcode {
    End = 0x00,
    PushLiteral = 0x01,
    PushCurrentAddress = 0x02,
    PushSymbol = 0x03,
    ApplyUnary = 0x04,
    ApplyBinary = 0x05,
    SelectTernary = 0x06,
}

impl ExprVmOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::End),
            0x01 => Some(Self::PushLiteral),
            0x02 => Some(Self::PushCurrentAddress),
            0x03 => Some(Self::PushSymbol),
            0x04 => Some(Self::ApplyUnary),
            0x05 => Some(Self::ApplyBinary),
            0x06 => Some(Self::SelectTernary),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExprVmUnary {
    Plus = 0,
    Minus = 1,
    BitNot = 2,
    LogicNot = 3,
    High = 4,
    Low = 5,
}

impl ExprVmUnary {
    fn from_core(op: UnaryOp) -> Self {
        match op {
            UnaryOp::Plus => Self::Plus,
            UnaryOp::Minus => Self::Minus,
            UnaryOp::BitNot => Self::BitNot,
            UnaryOp::LogicNot => Self::LogicNot,
            UnaryOp::High => Self::High,
            UnaryOp::Low => Self::Low,
        }
    }

    fn to_core(self) -> UnaryOp {
        match self {
            Self::Plus => UnaryOp::Plus,
            Self::Minus => UnaryOp::Minus,
            Self::BitNot => UnaryOp::BitNot,
            Self::LogicNot => UnaryOp::LogicNot,
            Self::High => UnaryOp::High,
            Self::Low => UnaryOp::Low,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Plus),
            1 => Some(Self::Minus),
            2 => Some(Self::BitNot),
            3 => Some(Self::LogicNot),
            4 => Some(Self::High),
            5 => Some(Self::Low),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExprVmBinary {
    Multiply = 0,
    Divide = 1,
    Mod = 2,
    Power = 3,
    Shl = 4,
    Shr = 5,
    Add = 6,
    Subtract = 7,
    Eq = 8,
    Ne = 9,
    Ge = 10,
    Gt = 11,
    Le = 12,
    Lt = 13,
    BitAnd = 14,
    BitOr = 15,
    BitXor = 16,
    LogicAnd = 17,
    LogicOr = 18,
    LogicXor = 19,
}

impl ExprVmBinary {
    fn from_core(op: BinaryOp) -> Self {
        match op {
            BinaryOp::Multiply => Self::Multiply,
            BinaryOp::Divide => Self::Divide,
            BinaryOp::Mod => Self::Mod,
            BinaryOp::Power => Self::Power,
            BinaryOp::Shl => Self::Shl,
            BinaryOp::Shr => Self::Shr,
            BinaryOp::Add => Self::Add,
            BinaryOp::Subtract => Self::Subtract,
            BinaryOp::Eq => Self::Eq,
            BinaryOp::Ne => Self::Ne,
            BinaryOp::Ge => Self::Ge,
            BinaryOp::Gt => Self::Gt,
            BinaryOp::Le => Self::Le,
            BinaryOp::Lt => Self::Lt,
            BinaryOp::BitAnd => Self::BitAnd,
            BinaryOp::BitOr => Self::BitOr,
            BinaryOp::BitXor => Self::BitXor,
            BinaryOp::LogicAnd => Self::LogicAnd,
            BinaryOp::LogicOr => Self::LogicOr,
            BinaryOp::LogicXor => Self::LogicXor,
        }
    }

    fn to_core(self) -> BinaryOp {
        match self {
            Self::Multiply => BinaryOp::Multiply,
            Self::Divide => BinaryOp::Divide,
            Self::Mod => BinaryOp::Mod,
            Self::Power => BinaryOp::Power,
            Self::Shl => BinaryOp::Shl,
            Self::Shr => BinaryOp::Shr,
            Self::Add => BinaryOp::Add,
            Self::Subtract => BinaryOp::Subtract,
            Self::Eq => BinaryOp::Eq,
            Self::Ne => BinaryOp::Ne,
            Self::Ge => BinaryOp::Ge,
            Self::Gt => BinaryOp::Gt,
            Self::Le => BinaryOp::Le,
            Self::Lt => BinaryOp::Lt,
            Self::BitAnd => BinaryOp::BitAnd,
            Self::BitOr => BinaryOp::BitOr,
            Self::BitXor => BinaryOp::BitXor,
            Self::LogicAnd => BinaryOp::LogicAnd,
            Self::LogicOr => BinaryOp::LogicOr,
            Self::LogicXor => BinaryOp::LogicXor,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Multiply),
            1 => Some(Self::Divide),
            2 => Some(Self::Mod),
            3 => Some(Self::Power),
            4 => Some(Self::Shl),
            5 => Some(Self::Shr),
            6 => Some(Self::Add),
            7 => Some(Self::Subtract),
            8 => Some(Self::Eq),
            9 => Some(Self::Ne),
            10 => Some(Self::Ge),
            11 => Some(Self::Gt),
            12 => Some(Self::Le),
            13 => Some(Self::Lt),
            14 => Some(Self::BitAnd),
            15 => Some(Self::BitOr),
            16 => Some(Self::BitXor),
            17 => Some(Self::LogicAnd),
            18 => Some(Self::LogicOr),
            19 => Some(Self::LogicXor),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortableExprRef {
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableExprProgram {
    pub opcode_version: u16,
    pub code: Vec<u8>,
    pub symbols: Vec<String>,
    pub declared_stack_depth: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableExprBudgets {
    pub max_program_bytes: usize,
    pub max_stack_depth: usize,
    pub max_symbol_refs: usize,
    pub max_eval_steps: usize,
}

impl Default for PortableExprBudgets {
    fn default() -> Self {
        Self {
            max_program_bytes: 2048,
            max_stack_depth: 64,
            max_symbol_refs: 128,
            max_eval_steps: 2048,
        }
    }
}

pub trait PortableExprEvalContext {
    fn lookup_symbol(&self, name: &str) -> Option<i64>;
    fn current_address(&self) -> Option<i64>;
    fn pass(&self) -> u8;
    fn symbol_is_finalized(&self, name: &str) -> Option<bool>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableExprEvaluation {
    pub value: i64,
    pub has_symbol_refs: bool,
    pub has_unstable_symbols: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableExprError {
    pub code: &'static str,
    pub message: String,
    pub span: Option<Span>,
}

impl PortableExprError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            span: None,
        }
    }

    fn with_span(code: &'static str, message: impl Into<String>, span: Span) -> Self {
        Self {
            code,
            message: message.into(),
            span: Some(span),
        }
    }
}

impl std::fmt::Display for PortableExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PortableExprError {}

pub const DIAG_EXPR_INVALID_OPCODE: &str = "ope001";
pub const DIAG_EXPR_STACK_UNDERFLOW: &str = "ope002";
pub const DIAG_EXPR_STACK_DEPTH_EXCEEDED: &str = "ope003";
pub const DIAG_EXPR_UNKNOWN_SYMBOL: &str = "ope004";
pub const DIAG_EXPR_EVAL_FAILURE: &str = "ope005";
pub const DIAG_EXPR_UNSUPPORTED_FEATURE: &str = "ope006";
pub const DIAG_EXPR_BUDGET_EXCEEDED: &str = "ope007";
pub const DIAG_EXPR_INVALID_PROGRAM: &str = "ope008";

pub fn compile_core_expr_to_portable_program(
    expr: &Expr,
) -> Result<PortableExprProgram, PortableExprError> {
    let mut compiler = ExprCompiler::default();
    compiler.compile(expr)?;
    compiler.emit_u8(ExprVmOpcode::End as u8);
    Ok(PortableExprProgram {
        opcode_version: EXPR_VM_OPCODE_VERSION_V1,
        code: compiler.code,
        symbols: compiler.symbols,
        declared_stack_depth: compiler.stack_max as u16,
    })
}

pub fn eval_portable_expr_program(
    program: &PortableExprProgram,
    ctx: &dyn PortableExprEvalContext,
    budgets: PortableExprBudgets,
) -> Result<PortableExprEvaluation, PortableExprError> {
    enforce_program_budgets(program, budgets)?;

    let mut stack: Vec<i64> = Vec::new();
    let mut ip = 0usize;
    let mut steps = 0usize;
    let mut has_symbol_refs = false;
    let mut has_unstable_symbols = false;

    while ip < program.code.len() {
        steps = steps.saturating_add(1);
        if steps > budgets.max_eval_steps {
            return Err(PortableExprError::new(
                DIAG_EXPR_BUDGET_EXCEEDED,
                format!(
                    "expression evaluation step budget exceeded ({} > {})",
                    steps, budgets.max_eval_steps
                ),
            ));
        }

        let opcode = read_opcode(&program.code, &mut ip)?;
        match opcode {
            ExprVmOpcode::End => break,
            ExprVmOpcode::PushLiteral => {
                let value = read_i64_le(&program.code, &mut ip)?;
                stack.push(value);
                enforce_stack_budget(&stack, budgets)?;
            }
            ExprVmOpcode::PushCurrentAddress => {
                let value = ctx.current_address().ok_or_else(|| {
                    PortableExprError::new(
                        DIAG_EXPR_EVAL_FAILURE,
                        "current address ($) not available",
                    )
                })?;
                stack.push(value);
                enforce_stack_budget(&stack, budgets)?;
            }
            ExprVmOpcode::PushSymbol => {
                let symbol_idx = read_u16_le(&program.code, &mut ip)? as usize;
                let Some(symbol_name) = program.symbols.get(symbol_idx) else {
                    return Err(PortableExprError::new(
                        DIAG_EXPR_INVALID_PROGRAM,
                        format!("symbol index out of range: {}", symbol_idx),
                    ));
                };

                has_symbol_refs = true;
                if ctx.lookup_symbol(symbol_name).is_none()
                    || (ctx.pass() > 1
                        && matches!(ctx.symbol_is_finalized(symbol_name), Some(false)))
                {
                    has_unstable_symbols = true;
                }

                let value = ctx.lookup_symbol(symbol_name).ok_or_else(|| {
                    PortableExprError::new(
                        DIAG_EXPR_UNKNOWN_SYMBOL,
                        format!("undefined symbol: {}", symbol_name),
                    )
                })?;
                stack.push(value);
                enforce_stack_budget(&stack, budgets)?;
            }
            ExprVmOpcode::ApplyUnary => {
                let unary =
                    ExprVmUnary::from_u8(read_u8(&program.code, &mut ip)?).ok_or_else(|| {
                        PortableExprError::new(DIAG_EXPR_INVALID_OPCODE, "invalid unary opcode")
                    })?;
                let value = pop_value(&mut stack)?;
                let result = apply_unary(unary.to_core(), value, Span::default())
                    .map_err(|err| PortableExprError::new(DIAG_EXPR_EVAL_FAILURE, err.message))?;
                stack.push(result);
            }
            ExprVmOpcode::ApplyBinary => {
                let binary =
                    ExprVmBinary::from_u8(read_u8(&program.code, &mut ip)?).ok_or_else(|| {
                        PortableExprError::new(DIAG_EXPR_INVALID_OPCODE, "invalid binary opcode")
                    })?;
                let right = pop_value(&mut stack)?;
                let left = pop_value(&mut stack)?;
                let result = apply_binary(binary.to_core(), left, right, Span::default())
                    .map_err(|err| PortableExprError::new(DIAG_EXPR_EVAL_FAILURE, err.message))?;
                stack.push(result);
            }
            ExprVmOpcode::SelectTernary => {
                let else_value = pop_value(&mut stack)?;
                let then_value = pop_value(&mut stack)?;
                let cond_value = pop_value(&mut stack)?;
                stack.push(if cond_value != 0 {
                    then_value
                } else {
                    else_value
                });
            }
        }
    }

    if stack.len() != 1 {
        return Err(PortableExprError::new(
            DIAG_EXPR_INVALID_PROGRAM,
            format!(
                "expression VM must finish with exactly one stack value; got {}",
                stack.len()
            ),
        ));
    }

    Ok(PortableExprEvaluation {
        value: stack[0],
        has_symbol_refs,
        has_unstable_symbols,
    })
}

pub fn expr_program_has_unstable_symbols(
    program: &PortableExprProgram,
    ctx: &dyn PortableExprEvalContext,
    budgets: PortableExprBudgets,
) -> Result<bool, PortableExprError> {
    enforce_program_budgets(program, budgets)?;
    let mut ip = 0usize;

    while ip < program.code.len() {
        let opcode = read_opcode(&program.code, &mut ip)?;
        match opcode {
            ExprVmOpcode::End => return Ok(false),
            ExprVmOpcode::PushLiteral => {
                read_i64_le(&program.code, &mut ip)?;
            }
            ExprVmOpcode::PushCurrentAddress => {}
            ExprVmOpcode::PushSymbol => {
                let symbol_idx = read_u16_le(&program.code, &mut ip)? as usize;
                let Some(symbol_name) = program.symbols.get(symbol_idx) else {
                    return Err(PortableExprError::new(
                        DIAG_EXPR_INVALID_PROGRAM,
                        format!("symbol index out of range: {}", symbol_idx),
                    ));
                };
                if ctx.lookup_symbol(symbol_name).is_none()
                    || (ctx.pass() > 1
                        && matches!(ctx.symbol_is_finalized(symbol_name), Some(false)))
                {
                    return Ok(true);
                }
            }
            ExprVmOpcode::ApplyUnary => {
                read_u8(&program.code, &mut ip)?;
            }
            ExprVmOpcode::ApplyBinary => {
                read_u8(&program.code, &mut ip)?;
            }
            ExprVmOpcode::SelectTernary => {}
        }
    }

    Ok(false)
}

fn enforce_program_budgets(
    program: &PortableExprProgram,
    budgets: PortableExprBudgets,
) -> Result<(), PortableExprError> {
    if program.opcode_version != EXPR_VM_OPCODE_VERSION_V1 {
        return Err(PortableExprError::new(
            DIAG_EXPR_INVALID_PROGRAM,
            format!(
                "unsupported expression VM opcode version {}",
                program.opcode_version
            ),
        ));
    }
    if program.code.len() > budgets.max_program_bytes {
        return Err(PortableExprError::new(
            DIAG_EXPR_BUDGET_EXCEEDED,
            format!(
                "expression VM program byte budget exceeded ({} > {})",
                program.code.len(),
                budgets.max_program_bytes
            ),
        ));
    }
    if program.symbols.len() > budgets.max_symbol_refs {
        return Err(PortableExprError::new(
            DIAG_EXPR_BUDGET_EXCEEDED,
            format!(
                "expression VM symbol reference budget exceeded ({} > {})",
                program.symbols.len(),
                budgets.max_symbol_refs
            ),
        ));
    }
    if (program.declared_stack_depth as usize) > budgets.max_stack_depth {
        return Err(PortableExprError::new(
            DIAG_EXPR_BUDGET_EXCEEDED,
            format!(
                "expression VM stack depth budget exceeded ({} > {})",
                program.declared_stack_depth, budgets.max_stack_depth
            ),
        ));
    }
    Ok(())
}

fn enforce_stack_budget(
    stack: &[i64],
    budgets: PortableExprBudgets,
) -> Result<(), PortableExprError> {
    if stack.len() > budgets.max_stack_depth {
        return Err(PortableExprError::new(
            DIAG_EXPR_STACK_DEPTH_EXCEEDED,
            format!(
                "expression VM stack depth exceeded ({} > {})",
                stack.len(),
                budgets.max_stack_depth
            ),
        ));
    }
    Ok(())
}

fn pop_value(stack: &mut Vec<i64>) -> Result<i64, PortableExprError> {
    stack.pop().ok_or_else(|| {
        PortableExprError::new(DIAG_EXPR_STACK_UNDERFLOW, "expression VM stack underflow")
    })
}

fn read_opcode(code: &[u8], ip: &mut usize) -> Result<ExprVmOpcode, PortableExprError> {
    let opcode = read_u8(code, ip)?;
    ExprVmOpcode::from_u8(opcode).ok_or_else(|| {
        PortableExprError::new(
            DIAG_EXPR_INVALID_OPCODE,
            format!("invalid expression VM opcode: 0x{opcode:02X}"),
        )
    })
}

fn read_u8(code: &[u8], ip: &mut usize) -> Result<u8, PortableExprError> {
    if *ip >= code.len() {
        return Err(PortableExprError::new(
            DIAG_EXPR_INVALID_PROGRAM,
            "unexpected end of expression VM program",
        ));
    }
    let value = code[*ip];
    *ip += 1;
    Ok(value)
}

fn read_u16_le(code: &[u8], ip: &mut usize) -> Result<u16, PortableExprError> {
    if code.len().saturating_sub(*ip) < 2 {
        return Err(PortableExprError::new(
            DIAG_EXPR_INVALID_PROGRAM,
            "unexpected end of expression VM program (u16)",
        ));
    }
    let value = u16::from_le_bytes([code[*ip], code[*ip + 1]]);
    *ip += 2;
    Ok(value)
}

fn read_i64_le(code: &[u8], ip: &mut usize) -> Result<i64, PortableExprError> {
    if code.len().saturating_sub(*ip) < 8 {
        return Err(PortableExprError::new(
            DIAG_EXPR_INVALID_PROGRAM,
            "unexpected end of expression VM program (i64)",
        ));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&code[*ip..*ip + 8]);
    *ip += 8;
    Ok(i64::from_le_bytes(bytes))
}

#[derive(Default)]
struct ExprCompiler {
    code: Vec<u8>,
    symbols: Vec<String>,
    symbol_index: HashMap<String, u16>,
    stack_cur: usize,
    stack_max: usize,
}

impl ExprCompiler {
    fn compile(&mut self, expr: &Expr) -> Result<(), PortableExprError> {
        match expr {
            Expr::Number(text, span) => {
                let value = parse_number(text).ok_or_else(|| {
                    PortableExprError::with_span(
                        DIAG_EXPR_EVAL_FAILURE,
                        format!("invalid number: {}", text),
                        *span,
                    )
                })?;
                self.emit_u8(ExprVmOpcode::PushLiteral as u8);
                self.emit_i64(value);
                self.stack_push();
                Ok(())
            }
            Expr::Identifier(name, _) | Expr::Register(name, _) => {
                let symbol_idx = self.intern_symbol(name)?;
                self.emit_u8(ExprVmOpcode::PushSymbol as u8);
                self.emit_u16(symbol_idx);
                self.stack_push();
                Ok(())
            }
            Expr::Dollar(_) => {
                self.emit_u8(ExprVmOpcode::PushCurrentAddress as u8);
                self.stack_push();
                Ok(())
            }
            Expr::Unary { op, expr, .. } => {
                self.compile(expr)?;
                self.emit_u8(ExprVmOpcode::ApplyUnary as u8);
                self.emit_u8(ExprVmUnary::from_core(*op) as u8);
                Ok(())
            }
            Expr::Binary {
                op, left, right, ..
            } => {
                self.compile(left)?;
                self.compile(right)?;
                self.emit_u8(ExprVmOpcode::ApplyBinary as u8);
                self.emit_u8(ExprVmBinary::from_core(*op) as u8);
                self.stack_pop()?;
                Ok(())
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                self.compile(cond)?;
                self.compile(then_expr)?;
                self.compile(else_expr)?;
                self.emit_u8(ExprVmOpcode::SelectTernary as u8);
                self.stack_pop()?;
                self.stack_pop()?;
                Ok(())
            }
            Expr::Indirect(inner, _) | Expr::IndirectLong(inner, _) => self.compile(inner),
            Expr::Immediate(_, span) => Err(PortableExprError::with_span(
                DIAG_EXPR_UNSUPPORTED_FEATURE,
                "immediate expression shape is not supported by portable expression VM",
                *span,
            )),
            Expr::Tuple(_, span) => Err(PortableExprError::with_span(
                DIAG_EXPR_UNSUPPORTED_FEATURE,
                "tuple expression is not supported by portable expression VM",
                *span,
            )),
            Expr::String(_, span) => Err(PortableExprError::with_span(
                DIAG_EXPR_UNSUPPORTED_FEATURE,
                "string expression is not supported by portable expression VM",
                *span,
            )),
            Expr::Error(message, span) => Err(PortableExprError::with_span(
                DIAG_EXPR_UNSUPPORTED_FEATURE,
                message.clone(),
                *span,
            )),
        }
    }

    fn intern_symbol(&mut self, name: &str) -> Result<u16, PortableExprError> {
        if let Some(index) = self.symbol_index.get(name) {
            return Ok(*index);
        }
        let next = u16::try_from(self.symbols.len()).map_err(|_| {
            PortableExprError::new(
                DIAG_EXPR_BUDGET_EXCEEDED,
                "expression symbol table exceeds u16 capacity",
            )
        })?;
        self.symbols.push(name.to_string());
        self.symbol_index.insert(name.to_string(), next);
        Ok(next)
    }

    fn stack_push(&mut self) {
        self.stack_cur += 1;
        if self.stack_cur > self.stack_max {
            self.stack_max = self.stack_cur;
        }
    }

    fn stack_pop(&mut self) -> Result<(), PortableExprError> {
        if self.stack_cur == 0 {
            return Err(PortableExprError::new(
                DIAG_EXPR_INVALID_PROGRAM,
                "compiler stack tracking underflow",
            ));
        }
        self.stack_cur -= 1;
        Ok(())
    }

    fn emit_u8(&mut self, value: u8) {
        self.code.push(value);
    }

    fn emit_u16(&mut self, value: u16) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    fn emit_i64(&mut self, value: i64) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestCtx {
        symbols: HashMap<String, i64>,
        finalized: HashMap<String, bool>,
        addr: Option<i64>,
        pass: u8,
    }

    impl PortableExprEvalContext for TestCtx {
        fn lookup_symbol(&self, name: &str) -> Option<i64> {
            self.symbols.get(name).copied()
        }

        fn current_address(&self) -> Option<i64> {
            self.addr
        }

        fn pass(&self) -> u8 {
            self.pass
        }

        fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
            self.finalized.get(name).copied()
        }
    }

    fn span() -> Span {
        Span {
            line: 1,
            col_start: 1,
            col_end: 1,
        }
    }

    #[test]
    fn eval_arithmetic_program() {
        let expr = Expr::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::Number("2".to_string(), span())),
            right: Box::new(Expr::Binary {
                op: BinaryOp::Multiply,
                left: Box::new(Expr::Number("3".to_string(), span())),
                right: Box::new(Expr::Number("4".to_string(), span())),
                span: span(),
            }),
            span: span(),
        };
        let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");
        let result = eval_portable_expr_program(&program, &TestCtx::default(), Default::default())
            .expect("eval should work");
        assert_eq!(result.value, 14);
    }

    #[test]
    fn eval_dollar_uses_current_address() {
        let expr = Expr::Dollar(span());
        let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");
        let ctx = TestCtx {
            addr: Some(0x1234),
            ..Default::default()
        };
        let result = eval_portable_expr_program(&program, &ctx, Default::default())
            .expect("eval should work");
        assert_eq!(result.value, 0x1234);
    }

    #[test]
    fn unstable_symbol_detection_matches_pass_rules() {
        let expr = Expr::Identifier("label".to_string(), span());
        let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");

        let pass1_unknown = TestCtx {
            pass: 1,
            ..Default::default()
        };
        assert!(
            expr_program_has_unstable_symbols(&program, &pass1_unknown, Default::default())
                .expect("scan should work")
        );

        let pass2_unfinalized = TestCtx {
            symbols: HashMap::from([("label".to_string(), 10)]),
            finalized: HashMap::from([("label".to_string(), false)]),
            pass: 2,
            ..Default::default()
        };
        assert!(expr_program_has_unstable_symbols(
            &program,
            &pass2_unfinalized,
            Default::default()
        )
        .expect("scan should work"));

        let pass2_finalized = TestCtx {
            symbols: HashMap::from([("label".to_string(), 10)]),
            finalized: HashMap::from([("label".to_string(), true)]),
            pass: 2,
            ..Default::default()
        };
        assert!(
            !expr_program_has_unstable_symbols(&program, &pass2_finalized, Default::default())
                .expect("scan should work")
        );
    }

    #[test]
    fn budget_exceeded_reports_stable_code() {
        let expr = Expr::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::Number("1".to_string(), span())),
            right: Box::new(Expr::Number("2".to_string(), span())),
            span: span(),
        };
        let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");
        let budgets = PortableExprBudgets {
            max_program_bytes: 1,
            ..Default::default()
        };
        let err = eval_portable_expr_program(&program, &TestCtx::default(), budgets)
            .expect_err("budget should fail");
        assert_eq!(err.code, DIAG_EXPR_BUDGET_EXCEEDED);
    }

    #[test]
    fn invalid_opcode_reports_stable_code() {
        let program = PortableExprProgram {
            opcode_version: EXPR_VM_OPCODE_VERSION_V1,
            code: vec![0xFE, ExprVmOpcode::End as u8],
            symbols: Vec::new(),
            declared_stack_depth: 1,
        };
        let err = eval_portable_expr_program(&program, &TestCtx::default(), Default::default())
            .expect_err("invalid opcode should fail");
        assert_eq!(err.code, DIAG_EXPR_INVALID_OPCODE);
    }
}
