// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Generic bytecode VM primitives used by family-specific adapters.

pub const OP_EMIT_U8: u8 = 0x01;
pub const OP_EMIT_OPERAND: u8 = 0x02;
pub const OP_END: u8 = 0xFF;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmError {
    TruncatedProgram,
    InvalidOpcode { opcode: u8, pc: usize },
    OperandIndexOutOfRange { index: usize, len: usize },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedProgram => write!(f, "truncated VM program"),
            Self::InvalidOpcode { opcode, pc } => {
                write!(f, "invalid VM opcode 0x{opcode:02X} at pc={pc}")
            }
            Self::OperandIndexOutOfRange { index, len } => {
                write!(
                    f,
                    "VM operand index out of range (index={index}, len={len})"
                )
            }
        }
    }
}

impl std::error::Error for VmError {}

pub fn execute_program(program: &[u8], operands: &[&[u8]]) -> Result<Vec<u8>, VmError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    loop {
        let opcode = *program.get(pc).ok_or(VmError::TruncatedProgram)?;
        pc += 1;
        match opcode {
            OP_EMIT_U8 => {
                let value = *program.get(pc).ok_or(VmError::TruncatedProgram)?;
                pc += 1;
                out.push(value);
            }
            OP_EMIT_OPERAND => {
                let index = *program.get(pc).ok_or(VmError::TruncatedProgram)? as usize;
                pc += 1;
                let bytes = operands.get(index).ok_or(VmError::OperandIndexOutOfRange {
                    index,
                    len: operands.len(),
                })?;
                out.extend_from_slice(bytes);
            }
            OP_END => return Ok(out),
            _ => return Err(VmError::InvalidOpcode { opcode, pc: pc - 1 }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_literal_and_operand_stream() {
        let program = [OP_EMIT_U8, 0xA9, OP_EMIT_OPERAND, 0x00, OP_END];
        let operand = [0x42];
        let out = execute_program(&program, &[&operand]).expect("program should execute");
        assert_eq!(out, vec![0xA9, 0x42]);
    }

    #[test]
    fn reports_operand_index_out_of_range() {
        let program = [OP_EMIT_OPERAND, 0x01, OP_END];
        let err = execute_program(&program, &[&[0x42]]).expect_err("operand index should fail");
        assert!(matches!(err, VmError::OperandIndexOutOfRange { .. }));
    }
}
