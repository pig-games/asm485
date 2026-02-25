use crate::core::expr_vm::compile_core_expr_to_portable_program;
use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, CpuHandler, FamilyHandler};
use crate::core::parser::Expr;
use crate::core::registry::VmEncodeCandidate;
use crate::families::intel8080::handler::resolve_operands as resolve_intel8080_operands;
use crate::families::intel8080::table::{
    lookup_instruction, ArgType as IntelArgType, InstructionEntry as IntelInstructionEntry,
};
use crate::families::intel8080::{Intel8080FamilyHandler, Operand as IntelOperand};
use crate::families::mos6502::{FamilyOperand, MOS6502FamilyHandler, OperandForce};
use crate::i8085::extensions::lookup_extension as lookup_i8085_extension;
use crate::i8085::handler::I8085CpuHandler;
use crate::z80::extensions::lookup_extension as lookup_z80_extension;
use crate::z80::handler::Z80CpuHandler;

use super::selector_encoding::{input_shape_requires_m65816, selector_to_candidate};
use super::{force_suffix, HierarchyExecutionModel, ResolvedHierarchy, RuntimeBridgeError};

pub(super) fn intel8080_candidate_from_resolved(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
    ctx: &dyn AssemblerContext,
) -> Option<VmEncodeCandidate> {
    let normalized_operands;
    let operands =
        if let Some(stripped) = intel8080_strip_redundant_condition_operand(mnemonic, operands) {
            normalized_operands = stripped;
            normalized_operands.as_slice()
        } else {
            operands
        };

    if let Some(candidate) = intel8080_ld_indirect_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_half_index_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_cb_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_indexed_memory_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_indexed_cb_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }

    let entry = intel8080_lookup_instruction_entry(mnemonic, cpu_id, operands)?;
    if matches!(entry.arg_type, IntelArgType::Im) {
        let mode = intel8080_interrupt_mode_for_entry(entry, operands)?;
        let mode_key = crate::vm::intel8080_vm::mode_key_for_z80_interrupt_mode(mode)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }
    let operand_bytes = intel8080_operand_bytes_for_entry(entry, operands, ctx)?;
    Some(VmEncodeCandidate {
        mode_key: crate::vm::intel8080_vm::mode_key_for_instruction_entry(entry),
        operand_bytes,
    })
}

fn intel8080_lookup_instruction_entry(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<&'static IntelInstructionEntry> {
    let reg1 = operands.first().and_then(intel8080_lookup_key);
    let reg2 = operands.get(1).and_then(intel8080_lookup_key);

    if let Some(entry) = lookup_instruction(mnemonic, reg1.as_deref(), reg2.as_deref()) {
        return Some(entry);
    }
    if cpu_id.eq_ignore_ascii_case("8085") {
        return lookup_i8085_extension(mnemonic, reg1.as_deref(), reg2.as_deref());
    }
    if cpu_id.eq_ignore_ascii_case("z80") {
        return lookup_z80_extension(mnemonic, reg1.as_deref(), reg2.as_deref());
    }
    None
}

fn intel8080_strip_redundant_condition_operand(
    mnemonic: &str,
    operands: &[IntelOperand],
) -> Option<Vec<IntelOperand>> {
    let suffix = intel8080_condition_suffix_for_mnemonic(mnemonic)?;
    let first = operands.first()?;
    let condition = match first {
        IntelOperand::Condition(name, _) | IntelOperand::Register(name, _) => name.as_str(),
        _ => return None,
    };
    if !condition.eq_ignore_ascii_case(suffix) {
        return None;
    }
    Some(operands[1..].to_vec())
}

fn intel8080_condition_suffix_for_mnemonic(mnemonic: &str) -> Option<&'static str> {
    match mnemonic.to_ascii_uppercase().as_str() {
        "JNZ" | "CNZ" | "RNZ" => Some("NZ"),
        "JZ" | "CZ" | "RZ" => Some("Z"),
        "JNC" | "CNC" | "RNC" => Some("NC"),
        "JC" | "CC" | "RC" => Some("C"),
        "JPO" | "CPO" | "RPO" => Some("PO"),
        "JPE" | "CPE" | "RPE" => Some("PE"),
        "JP" | "CP" | "RP" => Some("P"),
        "JM" | "CM" | "RM" => Some("M"),
        _ => None,
    }
}

fn intel8080_lookup_key(operand: &IntelOperand) -> Option<String> {
    match operand {
        IntelOperand::Register(name, _) => Some(name.to_string()),
        IntelOperand::Indirect(name, _) if name.eq_ignore_ascii_case("hl") => Some("M".to_string()),
        IntelOperand::Indirect(name, _) => Some(name.to_string()),
        IntelOperand::Indexed { base, offset, .. } if *offset == 0 => Some(base.to_string()),
        IntelOperand::Condition(name, _) => Some(name.to_string()),
        IntelOperand::RstVector(value, _)
        | IntelOperand::InterruptMode(value, _)
        | IntelOperand::BitNumber(value, _) => Some(value.to_string()),
        _ => None,
    }
}

fn intel8080_operand_bytes_for_entry(
    entry: &IntelInstructionEntry,
    operands: &[IntelOperand],
    ctx: &dyn AssemblerContext,
) -> Option<Vec<Vec<u8>>> {
    let imm_index = entry.num_regs as usize;
    match entry.arg_type {
        IntelArgType::None => Some(Vec::new()),
        IntelArgType::Byte => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate8(value, _)
                | IntelOperand::Port(value, _)
                | IntelOperand::RstVector(value, _)
                | IntelOperand::InterruptMode(value, _)
                | IntelOperand::BitNumber(value, _) => *value,
                _ => return None,
            };
            Some(vec![vec![value]])
        }
        IntelArgType::Word => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate16(value, _) | IntelOperand::IndirectAddress16(value, _) => {
                    *value
                }
                _ => return None,
            };
            Some(vec![vec![value as u8, (value >> 8) as u8]])
        }
        IntelArgType::Relative => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate8(value, _) => *value,
                IntelOperand::Immediate16(target, _) => {
                    let next_pc = ctx.current_address() as i64
                        + crate::vm::intel8080_vm::prefix_len(entry.prefix) as i64
                        + 2;
                    let delta = *target as i64 - next_pc;
                    if !(-128..=127).contains(&delta) {
                        return None;
                    }
                    delta as i8 as u8
                }
                _ => return None,
            };
            Some(vec![vec![value]])
        }
        IntelArgType::Im => None,
    }
}

fn intel8080_interrupt_mode_for_entry(
    entry: &IntelInstructionEntry,
    operands: &[IntelOperand],
) -> Option<u8> {
    if !matches!(entry.arg_type, IntelArgType::Im) {
        return None;
    }
    let imm_index = entry.num_regs as usize;
    let mode = match operands.get(imm_index)? {
        IntelOperand::InterruptMode(value, _) | IntelOperand::Immediate8(value, _) => *value,
        IntelOperand::Immediate16(value, _) => (*value).try_into().ok()?,
        _ => return None,
    };
    if mode <= 2 {
        Some(mode)
    } else {
        None
    }
}

pub(super) fn intel8080_ld_indirect_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80")
        || !mnemonic.eq_ignore_ascii_case("ld")
        || operands.len() != 2
    {
        return None;
    }

    let (mode_key, addr) = match (&operands[0], &operands[1]) {
        (IntelOperand::Register(dst, _), IntelOperand::IndirectAddress16(addr, _)) => (
            crate::vm::intel8080_vm::mode_key_for_z80_ld_indirect(dst.as_str(), false)?,
            *addr,
        ),
        (IntelOperand::IndirectAddress16(addr, _), IntelOperand::Register(src, _)) => (
            crate::vm::intel8080_vm::mode_key_for_z80_ld_indirect(src.as_str(), true)?,
            *addr,
        ),
        _ => return None,
    };

    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes: vec![vec![addr as u8, (addr >> 8) as u8]],
    })
}

fn intel8080_half_index_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let mut prefix: Option<&str> = None;
    for operand in operands {
        let IntelOperand::Register(name, _) = operand else {
            continue;
        };
        let Some((current_prefix, _)) = intel8080_half_index_parts(name) else {
            continue;
        };
        match prefix {
            None => prefix = Some(current_prefix),
            Some(existing) if existing.eq_ignore_ascii_case(current_prefix) => {}
            Some(_) => return None,
        }
    }
    let prefix = prefix?;
    let upper = mnemonic.to_ascii_uppercase();

    let (_opcode, operand_bytes, form) = match upper.as_str() {
        "LD" => {
            if operands.len() != 2 {
                return None;
            }
            match (&operands[0], &operands[1]) {
                (IntelOperand::Register(dst, _), IntelOperand::Register(src, _)) => {
                    let dst_code = intel8080_half_index_reg_code(prefix, dst)?;
                    let src_code = intel8080_half_index_reg_code(prefix, src)?;
                    (
                        0x40 | (dst_code << 3) | src_code,
                        Vec::new(),
                        format!("rr:{dst_code}:{src_code}"),
                    )
                }
                (IntelOperand::Register(dst, _), IntelOperand::Immediate8(value, _)) => {
                    let (dst_prefix, dst_code) = intel8080_half_index_parts(dst)?;
                    if !dst_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    (
                        0x06 | (dst_code << 3),
                        vec![vec![*value]],
                        format!("ri:{dst_code}"),
                    )
                }
                (IntelOperand::Register(dst, _), IntelOperand::Immediate16(value, _))
                    if *value <= 0xFF =>
                {
                    let (dst_prefix, dst_code) = intel8080_half_index_parts(dst)?;
                    if !dst_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    (
                        0x06 | (dst_code << 3),
                        vec![vec![*value as u8]],
                        format!("ri:{dst_code}"),
                    )
                }
                _ => return None,
            }
        }
        "INC" | "DEC" => {
            if operands.len() != 1 {
                return None;
            }
            let code = match &operands[0] {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = if upper == "INC" { 0x04 } else { 0x05 };
            (base | (code << 3), Vec::new(), format!("r:{code}"))
        }
        "ADD" | "ADC" | "SBC" => {
            if operands.len() != 2 || !intel8080_is_register_a(&operands[0]) {
                return None;
            }
            let code = match &operands[1] {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = match upper.as_str() {
                "ADD" => 0x80,
                "ADC" => 0x88,
                "SBC" => 0x98,
                _ => return None,
            };
            (base | code, Vec::new(), format!("r:{code}"))
        }
        "SUB" | "AND" | "XOR" | "OR" | "CP" => {
            let src = match operands {
                [src] => src,
                [dst, src] if intel8080_is_register_a(dst) => src,
                _ => return None,
            };
            let code = match src {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = match upper.as_str() {
                "SUB" => 0x90,
                "AND" => 0xA0,
                "XOR" => 0xA8,
                "OR" => 0xB0,
                "CP" => 0xB8,
                _ => return None,
            };
            (base | code, Vec::new(), format!("r:{code}"))
        }
        _ => return None,
    };

    let mode_key =
        crate::vm::intel8080_vm::mode_key_for_z80_half_index(prefix, mnemonic, form.as_str())?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes,
    })
}

fn intel8080_half_index_parts(name: &str) -> Option<(&'static str, u8)> {
    match name.to_ascii_uppercase().as_str() {
        "IXH" => Some(("IX", 4)),
        "IXL" => Some(("IX", 5)),
        "IYH" => Some(("IY", 4)),
        "IYL" => Some(("IY", 5)),
        _ => None,
    }
}

fn intel8080_half_index_reg_code(prefix: &str, name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "B" => Some(0),
        "C" => Some(1),
        "D" => Some(2),
        "E" => Some(3),
        "A" => Some(7),
        _ => {
            let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
            if reg_prefix.eq_ignore_ascii_case(prefix) {
                Some(reg_code)
            } else {
                None
            }
        }
    }
}

fn intel8080_cb_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let upper = mnemonic.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL"
    ) {
        if operands.len() != 1 {
            return None;
        }
        let reg = intel8080_cb_register_name(&operands[0])?;
        let mode_key = crate::vm::intel8080_vm::mode_key_for_z80_cb_register(&upper, None, reg)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }

    if matches!(upper.as_str(), "BIT" | "RES" | "SET") {
        if operands.len() != 2 || intel8080_indexed_base_disp(&operands[1]).is_some() {
            return None;
        }
        let bit = intel8080_bit_value(&operands[0])?;
        let reg = intel8080_cb_register_name(&operands[1])?;
        let mode_key =
            crate::vm::intel8080_vm::mode_key_for_z80_cb_register(&upper, Some(bit), reg)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }

    None
}

fn intel8080_indexed_memory_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let (indexed_pos, base, displacement) = intel8080_single_indexed_operand(operands)?;
    let upper = mnemonic.to_ascii_uppercase();

    let (form, operand_bytes) = match upper.as_str() {
        "LD" => {
            if operands.len() != 2 {
                return None;
            }
            match (&operands[0], &operands[1], indexed_pos) {
                (IntelOperand::Register(dst, _), IntelOperand::Indexed { .. }, 1) => {
                    let _ = intel8080_z80_indexed_reg_code(dst)?;
                    (
                        format!("ld_r_from_idx_{}", dst.to_ascii_lowercase()),
                        vec![vec![displacement]],
                    )
                }
                (IntelOperand::Indexed { .. }, IntelOperand::Register(src, _), 0) => {
                    let _ = intel8080_z80_indexed_reg_code(src)?;
                    (
                        format!("ld_idx_from_r_{}", src.to_ascii_lowercase()),
                        vec![vec![displacement]],
                    )
                }
                (IntelOperand::Indexed { .. }, IntelOperand::Immediate8(value, _), 0) => (
                    "ld_idx_imm".to_string(),
                    vec![vec![displacement], vec![*value]],
                ),
                _ => return None,
            }
        }
        "INC" | "DEC" if operands.len() == 1 && indexed_pos == 0 => (
            if upper == "INC" {
                "inc_idx".to_string()
            } else {
                "dec_idx".to_string()
            },
            vec![vec![displacement]],
        ),
        "ADD" | "ADC" | "SBC"
            if operands.len() == 2 && indexed_pos == 1 && intel8080_is_register_a(&operands[0]) =>
        {
            let form = match upper.as_str() {
                "ADD" => "add_a_idx",
                "ADC" => "adc_a_idx",
                "SBC" => "sbc_a_idx",
                _ => return None,
            };
            (form.to_string(), vec![vec![displacement]])
        }
        "SUB"
            if (indexed_pos == 0 && operands.len() == 1)
                || (indexed_pos == 1
                    && operands.len() == 2
                    && intel8080_is_register_a(&operands[0])) =>
        {
            ("sub_idx".to_string(), vec![vec![displacement]])
        }
        "AND" | "XOR" | "OR" | "CP"
            if (indexed_pos == 0 && operands.len() == 1)
                || (indexed_pos == 1
                    && operands.len() == 2
                    && intel8080_is_register_a(&operands[0])) =>
        {
            let form = match upper.as_str() {
                "AND" => "and_idx",
                "XOR" => "xor_idx",
                "OR" => "or_idx",
                "CP" => "cp_idx",
                _ => return None,
            };
            (form.to_string(), vec![vec![displacement]])
        }
        _ => return None,
    };

    let mode_key = crate::vm::intel8080_vm::mode_key_for_z80_indexed_memory(base, form.as_str())?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes,
    })
}

fn intel8080_single_indexed_operand(operands: &[IntelOperand]) -> Option<(usize, &str, u8)> {
    let mut found = None;
    for (idx, operand) in operands.iter().enumerate() {
        let Some((base, displacement)) = intel8080_indexed_base_disp(operand) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some((idx, base, displacement));
    }
    found
}

fn intel8080_z80_indexed_reg_code(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "B" => Some(0),
        "C" => Some(1),
        "D" => Some(2),
        "E" => Some(3),
        "H" => Some(4),
        "L" => Some(5),
        "A" => Some(7),
        _ => None,
    }
}

fn intel8080_is_register_a(operand: &IntelOperand) -> bool {
    matches!(operand, IntelOperand::Register(name, _) if name.eq_ignore_ascii_case("a"))
}

fn intel8080_indexed_cb_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let upper = mnemonic.to_ascii_uppercase();
    let (base, displacement) = match upper.as_str() {
        "BIT" | "RES" | "SET" => {
            if operands.len() != 2 {
                return None;
            }
            let bit = intel8080_bit_value(&operands[0])?;
            let (base, displacement) = intel8080_indexed_base_disp(&operands[1])?;
            let mode_key =
                crate::vm::intel8080_vm::mode_key_for_z80_indexed_cb(base, &upper, Some(bit))?;
            return Some(VmEncodeCandidate {
                mode_key,
                operand_bytes: vec![vec![displacement]],
            });
        }
        "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL" => {
            if operands.len() != 1 {
                return None;
            }
            intel8080_indexed_base_disp(&operands[0])?
        }
        _ => return None,
    };

    let mode_key = crate::vm::intel8080_vm::mode_key_for_z80_indexed_cb(base, &upper, None)?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes: vec![vec![displacement]],
    })
}

fn intel8080_indexed_base_disp(operand: &IntelOperand) -> Option<(&str, u8)> {
    match operand {
        IntelOperand::Indexed { base, offset, .. }
            if base.eq_ignore_ascii_case("ix") || base.eq_ignore_ascii_case("iy") =>
        {
            Some((base.as_str(), *offset as u8))
        }
        _ => None,
    }
}

fn intel8080_bit_value(operand: &IntelOperand) -> Option<u8> {
    let bit = match operand {
        IntelOperand::BitNumber(value, _) | IntelOperand::Immediate8(value, _) => *value,
        IntelOperand::Immediate16(value, _) => (*value).try_into().ok()?,
        _ => return None,
    };
    if bit <= 7 {
        Some(bit)
    } else {
        None
    }
}

fn intel8080_cb_register_name(operand: &IntelOperand) -> Option<&str> {
    match operand {
        IntelOperand::Register(name, _) => Some(name.as_str()),
        IntelOperand::Indirect(name, _) if name.eq_ignore_ascii_case("hl") => Some("M"),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub(super) struct SelectorInput<'a> {
    pub(super) shape_key: String,
    pub(super) expr0: Option<&'a Expr>,
    pub(super) expr1: Option<&'a Expr>,
    pub(super) force: Option<OperandForce>,
}

pub(super) struct SelectorExprContext<'a> {
    pub(super) model: &'a HierarchyExecutionModel,
    pub(super) resolved: &'a ResolvedHierarchy,
    pub(super) assembler_ctx: &'a dyn AssemblerContext,
    pub(super) use_portable_eval: bool,
}

impl<'a> SelectorExprContext<'a> {
    fn is_unknown_symbol_error(message: &str) -> bool {
        let trimmed = message.trim_start();
        trimmed == "ope004" || trimmed.starts_with("ope004:")
    }

    fn allows_host_eval_compat_fallback(message: &str) -> bool {
        Self::is_unknown_symbol_error(message)
    }

    pub(super) fn new(
        model: &'a HierarchyExecutionModel,
        resolved: &'a ResolvedHierarchy,
        assembler_ctx: &'a dyn AssemblerContext,
    ) -> Self {
        let use_portable_eval = crate::vm::rollout::package_runtime_default_enabled_for_family(
            resolved.family_id.as_str(),
        );
        Self {
            model,
            resolved,
            assembler_ctx,
            use_portable_eval,
        }
    }

    pub(super) fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
        if !self.use_portable_eval {
            return self.assembler_ctx.eval_expr(expr);
        }
        let program = compile_core_expr_to_portable_program(expr).map_err(|err| err.to_string())?;
        match self
            .model
            .evaluate_portable_expression_program_with_contract_for_assembler(
                self.resolved.cpu_id.as_str(),
                Some(self.resolved.dialect_id.as_str()),
                &program,
                self.assembler_ctx,
            ) {
            Ok(evaluation) => Ok(evaluation.value),
            Err(err) => {
                let message = err.to_string();
                if Self::allows_host_eval_compat_fallback(message.as_str()) {
                    return self.assembler_ctx.eval_expr(expr);
                }
                Err(message)
            }
        }
    }

    pub(super) fn has_unstable_symbols(&self, expr: &Expr) -> Result<bool, String> {
        if !self.use_portable_eval {
            return Ok(expr_has_unstable_symbols(expr, self.assembler_ctx));
        }
        let program = compile_core_expr_to_portable_program(expr).map_err(|err| err.to_string())?;
        match self
            .model
            .portable_expression_has_unstable_symbols_with_contract_for_assembler(
                self.resolved.cpu_id.as_str(),
                Some(self.resolved.dialect_id.as_str()),
                &program,
                self.assembler_ctx,
            ) {
            Ok(value) => Ok(value),
            Err(err) => {
                let message = err.to_string();
                if Self::allows_host_eval_compat_fallback(message.as_str()) {
                    return Ok(expr_has_unstable_symbols(expr, self.assembler_ctx));
                }
                Err(message)
            }
        }
    }
}

pub(super) fn selector_input_from_family_operands(
    operands: &[FamilyOperand],
) -> Option<SelectorInput<'_>> {
    match operands {
        [] => Some(SelectorInput {
            shape_key: "implied".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Accumulator(_)] => Some(SelectorInput {
            shape_key: "accumulator".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Immediate(expr)] => Some(SelectorInput {
            shape_key: "immediate".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Direct(expr)] => Some(SelectorInput {
            shape_key: "direct".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectX(expr)] => Some(SelectorInput {
            shape_key: "direct_x".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectY(expr)] => Some(SelectorInput {
            shape_key: "direct_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndexedIndirectX(expr) | FamilyOperand::IndirectX(expr)] => {
            Some(SelectorInput {
                shape_key: "indexed_indirect_x".to_string(),
                expr0: Some(expr),
                expr1: None,
                force: None,
            })
        }
        [FamilyOperand::IndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "indirect_indexed_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectIndexedZ(expr)] => Some(SelectorInput {
            shape_key: "indirect_indexed_z".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Indirect(expr)] => Some(SelectorInput {
            shape_key: "indirect".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLong(expr)] => Some(SelectorInput {
            shape_key: "indirect_long".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLongY(expr)] => Some(SelectorInput {
            shape_key: "indirect_long_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLongZ(expr)] => Some(SelectorInput {
            shape_key: "indirect_long_z".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelative(expr)] => Some(SelectorInput {
            shape_key: "stack_relative".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelativeIndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "stack_relative_indirect_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::BlockMove { src, dst, .. }] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(src),
            expr1: Some(dst),
            force: None,
        }),
        [FamilyOperand::Forced { inner, force, .. }] => {
            let nested = selector_input_from_family_operands(std::slice::from_ref(inner.as_ref()))?;
            Some(SelectorInput {
                shape_key: format!("{}:force_{}", nested.shape_key, force_suffix(*force)),
                force: Some(*force),
                ..nested
            })
        }
        [FamilyOperand::Direct(first), FamilyOperand::Direct(second)] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(first),
            expr1: Some(second),
            force: None,
        }),
        _ => None,
    }
}

impl HierarchyExecutionModel {
    pub(super) fn select_candidates_from_exprs_mos6502(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let expr_ctx = SelectorExprContext::new(self, resolved, ctx);
        let family = MOS6502FamilyHandler::new();
        let parsed = family.parse_operands(mnemonic, operands).ok();
        let Some(input) = parsed
            .as_ref()
            .and_then(|operands| selector_input_from_family_operands(operands))
        else {
            return Ok(None);
        };

        let upper_mnemonic = mnemonic.to_ascii_uppercase();
        let lower_mnemonic = mnemonic.to_ascii_lowercase();
        let Some(mnemonic_id) = self.interned_id(&lower_mnemonic) else {
            return Ok(None);
        };
        let shape_key = input.shape_key.to_ascii_lowercase();
        let Some(shape_id) = self.interned_id(&shape_key) else {
            return Ok(None);
        };
        if !resolved.cpu_id.eq_ignore_ascii_case("65816")
            && input_shape_requires_m65816(&input.shape_key)
        {
            return Err(RuntimeBridgeError::Resolve(
                self.non_m65816_force_error(&resolved.cpu_id),
            ));
        }
        let owner_order = self.scoped_owner_lookup_order(resolved);

        let unstable_expr = match input.expr0 {
            Some(expr) => expr_ctx
                .has_unstable_symbols(expr)
                .map_err(RuntimeBridgeError::Resolve)?,
            None => false,
        };
        let mut candidates = Vec::new();
        let mut candidate_error: Option<String> = None;
        let mut saw_selector = false;
        let mut selectors_scanned = 0usize;

        for (owner_tag, owner_id) in owner_order {
            let Some(owner_id) = owner_id else {
                continue;
            };
            let key = (owner_tag, owner_id, mnemonic_id, shape_id);
            let Some(selectors) = self.mode_selectors.get(&key) else {
                continue;
            };
            saw_selector = true;

            let has_wider = selectors.iter().any(|entry| {
                entry.width_rank > 1
                    && self.mode_exists_for_owner(entry, owner_tag, owner_id, mnemonic_id)
            });

            for selector in selectors {
                selectors_scanned += 1;
                if selectors_scanned > self.budget_limits.max_selectors_scanned_per_instruction {
                    return Err(Self::budget_error(
                        "selector_scan_count",
                        self.budget_limits.max_selectors_scanned_per_instruction,
                        selectors_scanned,
                    ));
                }
                if unstable_expr && selector.unstable_widen && has_wider {
                    continue;
                }
                match selector_to_candidate(selector, &input, &upper_mnemonic, &expr_ctx) {
                    Ok(Some(candidate)) => {
                        candidates.push(candidate);
                        if candidates.len() > self.budget_limits.max_candidate_count {
                            return Err(Self::budget_error(
                                "candidate_count",
                                self.budget_limits.max_candidate_count,
                                candidates.len(),
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(message) => {
                        if candidate_error.is_none() {
                            candidate_error = Some(message);
                        }
                    }
                }
            }
        }

        if !candidates.is_empty() {
            return Ok(Some(candidates));
        }

        if let Some(force) = input.force {
            if !resolved.cpu_id.eq_ignore_ascii_case("65816") {
                return Err(RuntimeBridgeError::Resolve(
                    self.non_m65816_force_error(&resolved.cpu_id),
                ));
            }
            if let Some(message) = candidate_error {
                return Err(RuntimeBridgeError::Resolve(message));
            }
            if !saw_selector {
                return Err(RuntimeBridgeError::Resolve(
                    self.invalid_force_error(force, &upper_mnemonic),
                ));
            }
        }

        if let Some(message) = candidate_error {
            return Err(RuntimeBridgeError::Resolve(message));
        }

        Ok(None)
    }

    pub(super) fn select_candidates_from_exprs_intel8080(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let family = Intel8080FamilyHandler;
        let parsed = match family.parse_operands(mnemonic, operands) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(None),
        };

        let mut resolved_candidates: Vec<Vec<IntelOperand>> = Vec::new();

        if resolved.cpu_id.eq_ignore_ascii_case("z80") {
            if let Ok(ops) = Z80CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx) {
                resolved_candidates.push(ops);
            }
            if let Ok(ops) =
                resolve_intel8080_operands(mnemonic, &parsed, ctx).map_err(|err| err.message)
            {
                resolved_candidates.push(ops);
            }
        } else if resolved.cpu_id.eq_ignore_ascii_case("8085") {
            if let Ok(ops) = I8085CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx) {
                resolved_candidates.push(ops);
            }
        } else if let Ok(ops) =
            resolve_intel8080_operands(mnemonic, &parsed, ctx).map_err(|err| err.message)
        {
            resolved_candidates.push(ops);
        }

        for resolved_operands in &resolved_candidates {
            if let Some(candidate) = intel8080_candidate_from_resolved(
                mnemonic,
                resolved.cpu_id.as_str(),
                resolved_operands,
                ctx,
            ) {
                return Ok(Some(vec![candidate]));
            }
        }

        Ok(None)
    }
}
