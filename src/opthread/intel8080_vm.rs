// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel8080-family VM mode/program helpers shared by builder/runtime.

use crate::families::intel8080::table::{ArgType, InstructionEntry, Prefix};
use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};

pub(crate) fn mode_key_for_instruction_entry(entry: &InstructionEntry) -> String {
    format!(
        "p={};n={};r1={};r2={};a={}",
        prefix_key(entry.prefix),
        entry.num_regs,
        reg_key(entry.reg1),
        reg_key(entry.reg2),
        arg_type_key(entry.arg_type),
    )
}

pub(crate) fn compile_vm_program_for_instruction_entry(
    entry: &InstructionEntry,
) -> Option<Vec<u8>> {
    // IM and DD/FD CB forms still require host-side encode specialization.
    if matches!(entry.arg_type, ArgType::Im) {
        return None;
    }
    if matches!(entry.prefix, Prefix::DdCb | Prefix::FdCb) {
        return None;
    }

    let mut program = Vec::new();
    for &prefix in prefix_bytes(entry.prefix) {
        program.push(OP_EMIT_U8);
        program.push(prefix);
    }
    program.push(OP_EMIT_U8);
    program.push(entry.opcode);

    if matches!(
        entry.arg_type,
        ArgType::Byte | ArgType::Word | ArgType::Relative
    ) {
        program.push(OP_EMIT_OPERAND);
        program.push(0);
    }

    program.push(OP_END);
    Some(program)
}

#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
pub(crate) fn prefix_len(prefix: Prefix) -> usize {
    prefix_bytes(prefix).len()
}

fn prefix_bytes(prefix: Prefix) -> &'static [u8] {
    match prefix {
        Prefix::None => &[],
        Prefix::Cb => &[0xCB],
        Prefix::Dd => &[0xDD],
        Prefix::Ed => &[0xED],
        Prefix::Fd => &[0xFD],
        Prefix::DdCb => &[0xDD, 0xCB],
        Prefix::FdCb => &[0xFD, 0xCB],
    }
}

fn prefix_key(prefix: Prefix) -> &'static str {
    match prefix {
        Prefix::None => "none",
        Prefix::Cb => "cb",
        Prefix::Dd => "dd",
        Prefix::Ed => "ed",
        Prefix::Fd => "fd",
        Prefix::DdCb => "ddcb",
        Prefix::FdCb => "fdcb",
    }
}

fn arg_type_key(arg_type: ArgType) -> &'static str {
    match arg_type {
        ArgType::None => "none",
        ArgType::Byte => "byte",
        ArgType::Word => "word",
        ArgType::Relative => "rel",
        ArgType::Im => "im",
    }
}

fn reg_key(reg: &str) -> String {
    if reg.trim().is_empty() {
        "_".to_string()
    } else {
        reg.to_ascii_lowercase()
    }
}
