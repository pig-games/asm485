// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Minimal bytecode VM for MOS6502 family/base 6502 instruction emission.

use std::collections::HashMap;

use crate::families::mos6502::{AddressMode, Operand};
use crate::opthread::vm::{execute_program, VmError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Vm6502Error {
    MissingProgram { mnemonic: String, mode: AddressMode },
    Vm(VmError),
}

impl std::fmt::Display for Vm6502Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProgram { mnemonic, mode } => {
                write!(f, "missing VM program for {} {:?}", mnemonic, mode)
            }
            Self::Vm(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Vm6502Error {}

impl From<VmError> for Vm6502Error {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

#[derive(Clone, Debug)]
pub struct Mos6502VmProgramSet {
    programs: HashMap<String, Vec<u8>>,
}

impl Mos6502VmProgramSet {
    pub fn from_programs<I>(programs: I) -> Self
    where
        I: IntoIterator<Item = (String, String, Vec<u8>)>,
    {
        let mut out = HashMap::new();
        for (mnemonic, mode_key, program) in programs {
            out.insert(
                program_key_for_mode(mnemonic.as_str(), mode_key.as_str()),
                program,
            );
        }
        Self { programs: out }
    }

    pub fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Result<Vec<u8>, Vm6502Error> {
        if operands.is_empty() {
            let key = program_key(mnemonic, AddressMode::Implied);
            let program = self
                .programs
                .get(&key)
                .ok_or_else(|| Vm6502Error::MissingProgram {
                    mnemonic: mnemonic.to_ascii_uppercase(),
                    mode: AddressMode::Implied,
                })?;
            let no_operands: [&[u8]; 0] = [];
            return execute_program(program, &no_operands).map_err(Into::into);
        }

        let operand = &operands[0];
        for candidate in modes_to_try(operand) {
            let key = program_key(mnemonic, candidate.mode());
            if let Some(program) = self.programs.get(&key) {
                let operand_bytes = candidate.value_bytes();
                let vm_operands = [operand_bytes.as_slice()];
                return execute_program(program, &vm_operands).map_err(Into::into);
            }
        }

        Err(Vm6502Error::MissingProgram {
            mnemonic: mnemonic.to_ascii_uppercase(),
            mode: operand.mode(),
        })
    }
}

fn program_key(mnemonic: &str, mode: AddressMode) -> String {
    program_key_for_mode(mnemonic, format!("{mode:?}").as_str())
}

fn program_key_for_mode(mnemonic: &str, mode_key: &str) -> String {
    format!(
        "{}:{}",
        mnemonic.to_ascii_lowercase(),
        mode_key.to_ascii_lowercase()
    )
}

fn modes_to_try(operand: &Operand) -> Vec<Operand> {
    match operand {
        // Match native family mode promotion logic:
        // try zero-page first, then absolute if zero-page form is absent.
        Operand::ZeroPage(value, span) => {
            vec![operand.clone(), Operand::Absolute(*value as u16, *span)]
        }
        Operand::ZeroPageX(value, span) => {
            vec![operand.clone(), Operand::AbsoluteX(*value as u16, *span)]
        }
        Operand::ZeroPageY(value, span) => {
            vec![operand.clone(), Operand::AbsoluteY(*value as u16, *span)]
        }
        _ => vec![operand.clone()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tokenizer::Span;
    use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};

    fn sample_programs() -> Mos6502VmProgramSet {
        Mos6502VmProgramSet::from_programs([
            (
                "LDA".to_string(),
                "immediate".to_string(),
                vec![OP_EMIT_U8, 0xA9, OP_EMIT_OPERAND, 0x00, OP_END],
            ),
            (
                "JMP".to_string(),
                "absolute".to_string(),
                vec![OP_EMIT_U8, 0x4C, OP_EMIT_OPERAND, 0x00, OP_END],
            ),
        ])
    }

    #[test]
    fn vm_encodes_lda_immediate() {
        let vm = sample_programs();
        let bytes = vm
            .encode_instruction("LDA", &[Operand::Immediate(0x42, Span::default())])
            .expect("encode should succeed");
        assert_eq!(bytes, vec![0xA9, 0x42]);
    }

    #[test]
    fn vm_encodes_jmp_absolute() {
        let vm = sample_programs();
        let bytes = vm
            .encode_instruction("JMP", &[Operand::Absolute(0x1234, Span::default())])
            .expect("encode should succeed");
        assert_eq!(bytes, vec![0x4C, 0x34, 0x12]);
    }

    #[test]
    fn vm_promotes_jmp_zero_page_to_absolute() {
        let vm = sample_programs();
        let bytes = vm
            .encode_instruction("JMP", &[Operand::ZeroPage(0x10, Span::default())])
            .expect("encode should succeed");
        assert_eq!(bytes, vec![0x4C, 0x10, 0x00]);
    }
}
