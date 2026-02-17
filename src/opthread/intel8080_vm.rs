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
    // `IM` and indexed CB forms are emitted via dedicated helpers.
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

pub(crate) fn mode_key_for_z80_interrupt_mode(mode: u8) -> Option<String> {
    if mode > 2 {
        return None;
    }
    Some(format!("im={mode}"))
}

pub(crate) fn compile_vm_program_for_z80_interrupt_mode(mode: u8) -> Option<Vec<u8>> {
    let opcode = match mode {
        0 => 0x46,
        1 => 0x56,
        2 => 0x5E,
        _ => return None,
    };

    Some(vec![OP_EMIT_U8, 0xED, OP_EMIT_U8, opcode, OP_END])
}

pub(crate) fn mode_key_for_z80_indexed_cb(
    base: &str,
    mnemonic: &str,
    bit: Option<u8>,
) -> Option<String> {
    let base_key = indexed_cb_base_key(base)?;
    let upper = mnemonic.to_ascii_uppercase();
    let mnemonic_key = upper.to_ascii_lowercase();
    if matches!(upper.as_str(), "BIT" | "RES" | "SET") {
        let bit = bit?;
        if bit > 7 {
            return None;
        }
        Some(format!("cbidx={base_key}:{mnemonic_key}:{bit}"))
    } else {
        if bit.is_some() {
            return None;
        }
        if !matches!(
            upper.as_str(),
            "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL"
        ) {
            return None;
        }
        Some(format!("cbidx={base_key}:{mnemonic_key}"))
    }
}

pub(crate) fn compile_vm_program_for_z80_indexed_cb(
    base: &str,
    mnemonic: &str,
    bit: Option<u8>,
) -> Option<Vec<u8>> {
    let prefix = indexed_cb_prefix(base)?;
    let opcode = z80_indexed_cb_opcode(mnemonic, bit)?;

    Some(vec![
        OP_EMIT_U8,
        prefix,
        OP_EMIT_U8,
        0xCB,
        OP_EMIT_OPERAND,
        0,
        OP_EMIT_U8,
        opcode,
        OP_END,
    ])
}

pub(crate) fn mode_key_for_z80_indexed_memory(base: &str, form: &str) -> Option<String> {
    let base_key = indexed_cb_base_key(base)?;
    Some(format!("idxmem={base_key}:{}", form.to_ascii_lowercase()))
}

pub(crate) fn compile_vm_program_for_z80_indexed_memory(
    base: &str,
    opcode: u8,
    operand_count: u8,
) -> Option<Vec<u8>> {
    if !(1..=2).contains(&operand_count) {
        return None;
    }
    let prefix = indexed_cb_prefix(base)?;
    let mut program = vec![OP_EMIT_U8, prefix, OP_EMIT_U8, opcode, OP_EMIT_OPERAND, 0];
    if operand_count == 2 {
        program.push(OP_EMIT_OPERAND);
        program.push(1);
    }
    program.push(OP_END);
    Some(program)
}

pub(crate) fn mode_key_for_z80_ld_indirect(register: &str, store: bool) -> Option<String> {
    let reg = z80_ld_indirect_register_key(register)?;
    let dir = if store { "store" } else { "load" };
    Some(format!("ldind={dir}:{reg}"))
}

pub(crate) fn compile_vm_program_for_z80_ld_indirect(
    register: &str,
    store: bool,
) -> Option<Vec<u8>> {
    let (prefix, opcode) = z80_ld_indirect_prefix_opcode(register, store)?;
    let mut program = Vec::new();
    if let Some(prefix) = prefix {
        program.push(OP_EMIT_U8);
        program.push(prefix);
    }
    program.push(OP_EMIT_U8);
    program.push(opcode);
    program.push(OP_EMIT_OPERAND);
    program.push(0);
    program.push(OP_END);
    Some(program)
}

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

fn indexed_cb_prefix(base: &str) -> Option<u8> {
    match base.to_ascii_uppercase().as_str() {
        "IX" => Some(0xDD),
        "IY" => Some(0xFD),
        _ => None,
    }
}

fn indexed_cb_base_key(base: &str) -> Option<&'static str> {
    match base.to_ascii_uppercase().as_str() {
        "IX" => Some("ix"),
        "IY" => Some("iy"),
        _ => None,
    }
}

fn z80_indexed_cb_opcode(mnemonic: &str, bit: Option<u8>) -> Option<u8> {
    let upper = mnemonic.to_ascii_uppercase();
    match upper.as_str() {
        "RLC" => Some(0x06),
        "RRC" => Some(0x0E),
        "RL" => Some(0x16),
        "RR" => Some(0x1E),
        "SLA" => Some(0x26),
        "SRA" => Some(0x2E),
        "SLL" => Some(0x36),
        "SRL" => Some(0x3E),
        "BIT" | "RES" | "SET" => {
            let bit = bit?;
            if bit > 7 {
                return None;
            }
            let base = match upper.as_str() {
                "BIT" => 0x40,
                "RES" => 0x80,
                "SET" => 0xC0,
                _ => unreachable!(),
            };
            Some(base | (bit << 3) | 0x06)
        }
        _ => None,
    }
}

fn z80_ld_indirect_register_key(register: &str) -> Option<&'static str> {
    match register.to_ascii_uppercase().as_str() {
        "A" => Some("a"),
        "HL" => Some("hl"),
        "BC" => Some("bc"),
        "DE" => Some("de"),
        "SP" => Some("sp"),
        "IX" => Some("ix"),
        "IY" => Some("iy"),
        _ => None,
    }
}

fn z80_ld_indirect_prefix_opcode(register: &str, store: bool) -> Option<(Option<u8>, u8)> {
    match (register.to_ascii_uppercase().as_str(), store) {
        ("A", false) => Some((None, 0x3A)),
        ("A", true) => Some((None, 0x32)),
        ("HL", false) => Some((None, 0x2A)),
        ("HL", true) => Some((None, 0x22)),
        ("BC", false) => Some((Some(0xED), 0x4B)),
        ("BC", true) => Some((Some(0xED), 0x43)),
        ("DE", false) => Some((Some(0xED), 0x5B)),
        ("DE", true) => Some((Some(0xED), 0x53)),
        ("SP", false) => Some((Some(0xED), 0x7B)),
        ("SP", true) => Some((Some(0xED), 0x73)),
        ("IX", false) => Some((Some(0xDD), 0x2A)),
        ("IX", true) => Some((Some(0xDD), 0x22)),
        ("IY", false) => Some((Some(0xFD), 0x2A)),
        ("IY", true) => Some((Some(0xFD), 0x22)),
        _ => None,
    }
}
