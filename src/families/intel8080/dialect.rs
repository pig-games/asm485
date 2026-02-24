// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Dialect mapping for Intel 8080 family CPUs.
//!
//! This module maps dialect-specific mnemonics to their canonical family equivalents.
//! The family base instruction table uses Intel 8080 mnemonics as the canonical form.
//! Other dialects (e.g., Zilog Z80) are mapped to these canonical mnemonics.

use super::operand::FamilyOperand;
use crate::core::parser::Expr;

/// Result of dialect mapping.
#[derive(Debug, Clone)]
pub struct MappingResult<'a> {
    /// The canonical Intel mnemonic to look up.
    pub mnemonic: &'a str,
    /// First register operand (normalized to Intel names).
    pub reg1: Option<&'a str>,
    /// Second register operand (normalized to Intel names).
    pub reg2: Option<&'a str>,
    /// Whether an immediate/address operand follows.
    pub has_immediate: bool,
}

/// Maps a Z80 condition code to its Intel 8080 equivalent.
/// Returns the condition suffix used in Intel mnemonics (Z, NZ, C, NC, P, M, PE, PO).
pub fn map_condition(zilog_cond: &str) -> Option<&'static str> {
    match zilog_cond.to_ascii_uppercase().as_str() {
        "Z" => Some("Z"),
        "NZ" => Some("NZ"),
        "C" => Some("C"),
        "NC" => Some("NC"),
        "P" => Some("P"),   // Positive (sign flag clear)
        "M" => Some("M"),   // Minus (sign flag set)
        "PE" => Some("PE"), // Parity even
        "PO" => Some("PO"), // Parity odd
        _ => None,
    }
}

/// Operand class for pattern matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandClass {
    /// 8-bit register (A, B, C, D, E, H, L)
    Reg8,
    /// Memory via HL: (HL) or M
    MemHL,
    /// 16-bit register pair (BC, DE, HL, SP)
    Reg16,
    /// Condition code (Z, NZ, C, NC, P, M, PE, PO)
    Condition,
    /// Immediate byte
    Imm8,
    /// Immediate word / address
    Imm16,
    /// Indirect via register pair: (BC), (DE)
    IndirectRP,
    /// Indirect via address: (nnnn)
    IndirectAddr,
    /// Z80-only register (IX, IY, etc.)
    Z80Only,
}

/// Classify an operand string.
pub fn classify_operand(operand: &str) -> OperandClass {
    let upper = operand.to_ascii_uppercase();
    match upper.as_str() {
        // 8-bit registers
        "A" | "B" | "C" | "D" | "E" | "H" | "L" => OperandClass::Reg8,

        // Memory via HL (M is HL indirect, also used as "minus" condition in context)
        "M" | "(HL)" => OperandClass::MemHL,

        // 16-bit register pairs
        "BC" | "DE" | "HL" | "SP" | "AF" | "PSW" => OperandClass::Reg16,

        // Condition codes (when used as operands)
        // Note: "M" (minus) is handled above as MemHL - context determines meaning
        // Note: "C" is ambiguous - could be register or condition
        "Z" | "NZ" | "NC" | "P" | "PE" | "PO" => OperandClass::Condition,

        // Indirect via register pair
        "(BC)" | "(DE)" => OperandClass::IndirectRP,

        // Z80-only
        "IX" | "IY" | "IXH" | "IXL" | "IYH" | "IYL" | "I" | "R" => OperandClass::Z80Only,

        _ => {
            // Check for indirect address: (nnnn)
            if upper.starts_with('(') && upper.ends_with(')') {
                OperandClass::IndirectAddr
            } else {
                // Assume it's an immediate/expression
                OperandClass::Imm16
            }
        }
    }
}

/// Dialect mapping entry.
/// Maps a dialect-specific mnemonic pattern to the canonical family form.
pub struct DialectEntry {
    /// Dialect mnemonic (uppercase).
    pub from: &'static str,
    /// Expected number of register operands in dialect form.
    pub from_regs: u8,
    /// Whether dialect form has an immediate operand.
    pub from_has_imm: bool,
    /// Canonical family mnemonic.
    pub canonical: &'static str,
    /// Number of register operands in canonical form.
    pub canonical_regs: u8,
    /// Whether canonical form has an immediate operand.
    pub canonical_has_imm: bool,
    /// Special operand transformation.
    pub transform: OperandTransform,
}

/// How to transform operands from Zilog to Intel form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandTransform {
    /// Keep operands as-is.
    Identity,
    /// Drop the first operand (e.g., ADD A,B → ADD B).
    DropFirst,
    /// The first operand becomes a suffix on the mnemonic (e.g., JP Z,nn → JZ nn).
    ConditionSuffix,
    /// Map LDAX/STAX style: LD A,(BC) → LDAX B.
    IndirectLoad,
    /// Map LDAX/STAX style: LD (BC),A → STAX B.
    IndirectStore,
}

pub use crate::z80::dialect::ZILOG_DIALECT_MAP;

/// Distinct mnemonic surface supported by the Zilog dialect mapper.
pub fn zilog_dialect_mnemonics() -> Vec<String> {
    let mut mnemonics: Vec<String> = ZILOG_DIALECT_MAP
        .iter()
        .map(|entry| entry.from.to_ascii_lowercase())
        .collect();
    mnemonics.sort();
    mnemonics.dedup();
    mnemonics
}

/// Find a dialect mapping for a mnemonic in the Zilog dialect.
pub fn find_mapping(mnemonic: &str, num_regs: u8, has_imm: bool) -> Option<&'static DialectEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    ZILOG_DIALECT_MAP.iter().find(|entry| {
        entry.from == upper && entry.from_regs == num_regs && entry.from_has_imm == has_imm
    })
}

/// Suggest a canonical Intel8080-family mnemonic from a Zilog surface mnemonic.
///
/// This helper is intentionally mnemonic-only and does not validate operand arity;
/// callers should treat this as a hint unless full operand mapping succeeds.
pub fn canonical_suggestion_for_zilog_mnemonic(mnemonic: &str) -> Option<&'static str> {
    let upper = mnemonic.to_ascii_uppercase();
    ZILOG_DIALECT_MAP
        .iter()
        .find(|entry| entry.from == upper)
        .map(|entry| entry.canonical)
}

pub use crate::z80::dialect::{is_z80_only_mnemonic, map_register};

/// Map a Zilog mnemonic + operands to canonical Intel 8080 form.
///
/// Returns None if no mapping applies (caller should fall through to CPU extensions).
pub fn map_zilog_to_canonical(
    mnemonic: &str,
    operands: &[FamilyOperand],
) -> Option<(String, Vec<FamilyOperand>)> {
    if is_z80_only_mnemonic(mnemonic) {
        return None;
    }

    if operands
        .iter()
        .any(|op| matches!(op, FamilyOperand::Indexed { .. }))
    {
        return None;
    }

    let upper = mnemonic.to_ascii_uppercase();

    if upper == "LD" {
        return map_ld_operands(operands);
    }

    if upper == "EX" {
        if let Some(mapped) = map_ex_operands(operands) {
            return Some(mapped);
        }
    }

    if upper == "IN" {
        if let Some(mapped) = map_in_operands(operands) {
            return Some(mapped);
        }
    }

    if upper == "OUT" {
        if let Some(mapped) = map_out_operands(operands) {
            return Some(mapped);
        }
    }

    if upper == "JP" {
        if let Some(mapped) = map_jp_operands(operands) {
            return Some(mapped);
        }
    }

    if upper == "INC" || upper == "DEC" {
        if let Some(mapped) = map_inc_dec(&upper, operands) {
            return Some(mapped);
        }
    }

    if upper == "ADD" {
        if let Some(mapped) = map_add_hl(operands) {
            return Some(mapped);
        }
    }

    // ADC HL,rp and SBC HL,rp are Z80-only 16-bit operations (ED prefix).
    // They must NOT be dialect-mapped; return None so they fall through
    // to the Z80 extension table.
    if (upper == "ADC" || upper == "SBC") && is_16bit_hl_regpair(operands) {
        return None;
    }

    let (num_regs, has_imm) = count_regs_and_immediate(operands)?;
    let entry = find_mapping(&upper, num_regs, has_imm)?;
    let (mut canonical_mnemonic, mut canonical_operands) = apply_entry_mapping(entry, operands)?;

    if entry.canonical_has_imm {
        if let Some(imm) = operands.iter().find_map(immediate_expr) {
            canonical_operands.push(FamilyOperand::Immediate(imm));
        }
    }

    if entry.transform == OperandTransform::ConditionSuffix {
        canonical_mnemonic = apply_condition_suffix(entry.canonical, operands)?;
    }

    Some((canonical_mnemonic, canonical_operands))
}

fn count_regs_and_immediate(operands: &[FamilyOperand]) -> Option<(u8, bool)> {
    let mut regs = 0u8;
    let mut has_imm = false;

    for operand in operands {
        match operand {
            FamilyOperand::Register(_, _)
            | FamilyOperand::Indirect(_, _)
            | FamilyOperand::Condition(_, _) => regs = regs.saturating_add(1),
            FamilyOperand::Immediate(_) => has_imm = true,
            FamilyOperand::Indexed { .. } => return None,
            FamilyOperand::RstVector(_)
            | FamilyOperand::InterruptMode(_)
            | FamilyOperand::BitNumber(_)
            | FamilyOperand::Port(_) => has_imm = true,
        }
    }

    Some((regs, has_imm))
}

fn apply_entry_mapping(
    entry: &DialectEntry,
    operands: &[FamilyOperand],
) -> Option<(String, Vec<FamilyOperand>)> {
    if entry.transform == OperandTransform::IndirectLoad {
        return map_indirect_load(operands).map(|ops| (entry.canonical.to_string(), ops));
    }

    if entry.transform == OperandTransform::IndirectStore {
        return map_indirect_store(operands).map(|ops| (entry.canonical.to_string(), ops));
    }

    let mut reg_operands: Vec<FamilyOperand> = Vec::new();

    for operand in operands {
        if is_register_like(operand) {
            reg_operands.push(map_operand_register(operand)?);
        }
    }

    if entry.transform == OperandTransform::DropFirst && !reg_operands.is_empty() {
        reg_operands.remove(0);
    }

    if entry.transform == OperandTransform::ConditionSuffix && !reg_operands.is_empty() {
        reg_operands.remove(0);
    }

    let regs_needed = entry.canonical_regs as usize;
    if reg_operands.len() < regs_needed {
        return None;
    }

    reg_operands.truncate(regs_needed);

    Some((entry.canonical.to_string(), reg_operands))
}

fn map_ld_operands(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    if operands.len() != 2 {
        return None;
    }

    let op1 = &operands[0];
    let op2 = &operands[1];
    let class1 = operand_class(op1);
    let class2 = operand_class(op2);

    // Z80 memory-indirect LD forms (`(nn)`) are distinct from immediate loads.
    // Map forms with 8080 equivalents and leave remaining forms untouched so the
    // Z80 CPU handler can encode them.
    if let Some(addr) = immediate_indirect_expr(op2) {
        if is_register_named(op1, "A") {
            return Some(("LDA".to_string(), vec![FamilyOperand::Immediate(addr)]));
        }
        if is_register_named(op1, "HL") {
            return Some(("LHLD".to_string(), vec![FamilyOperand::Immediate(addr)]));
        }
        return None;
    }

    if let Some(addr) = immediate_indirect_expr(op1) {
        if is_register_named(op2, "A") {
            return Some(("STA".to_string(), vec![FamilyOperand::Immediate(addr)]));
        }
        if is_register_named(op2, "HL") {
            return Some(("SHLD".to_string(), vec![FamilyOperand::Immediate(addr)]));
        }
        return None;
    }

    if class1 == OperandClass::Reg16 && class2 == OperandClass::Imm16 {
        let reg = map_reg16(op1)?;
        let imm = immediate_expr(op2)?;
        return Some(("LXI".to_string(), vec![reg, FamilyOperand::Immediate(imm)]));
    }

    if class1 == OperandClass::Reg8 || class1 == OperandClass::MemHL {
        if class2 == OperandClass::Reg8 || class2 == OperandClass::MemHL {
            let reg1 = map_reg8_or_mem(op1)?;
            let reg2 = map_reg8_or_mem(op2)?;
            return Some(("MOV".to_string(), vec![reg1, reg2]));
        }

        if class2 == OperandClass::Imm16 {
            let reg = map_reg8_or_mem(op1)?;
            let imm = immediate_expr(op2)?;
            return Some(("MVI".to_string(), vec![reg, FamilyOperand::Immediate(imm)]));
        }

        if class2 == OperandClass::IndirectRP && is_register_named(op1, "A") {
            if let Some(reg) = map_indirect_regpair(op2) {
                return Some(("LDAX".to_string(), vec![reg]));
            }
        }
    }

    if class1 == OperandClass::IndirectRP
        && class2 == OperandClass::Reg8
        && is_register_named(op2, "A")
    {
        if let Some(reg) = map_indirect_regpair(op1) {
            return Some(("STAX".to_string(), vec![reg]));
        }
    }

    if is_sp_hl_pair(op1, op2) {
        return Some(("SPHL".to_string(), Vec::new()));
    }

    None
}

fn map_ex_operands(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    if operands.len() != 2 {
        return None;
    }

    let left = &operands[0];
    let right = &operands[1];

    if (is_register_named(left, "DE") && is_register_named(right, "HL"))
        || (is_register_named(left, "HL") && is_register_named(right, "DE"))
    {
        return Some(("XCHG".to_string(), Vec::new()));
    }

    if (is_indirect_named(left, "SP") && is_register_named(right, "HL"))
        || (is_register_named(left, "HL") && is_indirect_named(right, "SP"))
    {
        return Some(("XTHL".to_string(), Vec::new()));
    }

    None
}

fn map_in_operands(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    match operands {
        [FamilyOperand::Register(reg, _), port] if reg.eq_ignore_ascii_case("A") => {
            let expr = immediate_indirect_expr(port)?;
            Some(("IN".to_string(), vec![FamilyOperand::Port(expr)]))
        }
        _ => None,
    }
}

fn map_out_operands(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    match operands {
        [port, FamilyOperand::Register(reg, _)] if reg.eq_ignore_ascii_case("A") => {
            let expr = immediate_indirect_expr(port)?;
            Some(("OUT".to_string(), vec![FamilyOperand::Port(expr)]))
        }
        _ => None,
    }
}

fn map_jp_operands(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    match operands {
        [FamilyOperand::Indirect(name, _)] if name.eq_ignore_ascii_case("HL") => {
            Some(("PCHL".to_string(), Vec::new()))
        }
        [FamilyOperand::Immediate(expr)] => Some((
            "JMP".to_string(),
            vec![FamilyOperand::Immediate(expr.clone())],
        )),
        [first, FamilyOperand::Immediate(expr)] => {
            let suffix = match first {
                FamilyOperand::Condition(cond, _) => map_condition(cond),
                FamilyOperand::Register(cond, _) => map_condition(cond),
                _ => None,
            }?;
            Some((
                format!("J{suffix}"),
                vec![FamilyOperand::Immediate(expr.clone())],
            ))
        }
        _ => None,
    }
}

fn map_inc_dec(mnemonic: &str, operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    if operands.len() != 1 {
        return None;
    }

    let operand = &operands[0];
    let class = operand_class(operand);

    if class == OperandClass::Reg16 {
        let reg = map_reg16(operand)?;
        let canonical = if mnemonic == "INC" { "INX" } else { "DCX" };
        return Some((canonical.to_string(), vec![reg]));
    }

    if class == OperandClass::Reg8 || class == OperandClass::MemHL {
        let reg = map_reg8_or_mem(operand)?;
        let canonical = if mnemonic == "INC" { "INR" } else { "DCR" };
        return Some((canonical.to_string(), vec![reg]));
    }

    None
}

/// Check if operands represent a 16-bit `HL, rp` pattern (for ADC/SBC HL).
fn is_16bit_hl_regpair(operands: &[FamilyOperand]) -> bool {
    if operands.len() != 2 {
        return false;
    }
    is_register_named(&operands[0], "HL") && operand_class(&operands[1]) == OperandClass::Reg16
}

fn map_add_hl(operands: &[FamilyOperand]) -> Option<(String, Vec<FamilyOperand>)> {
    if operands.len() != 2 {
        return None;
    }

    let op1 = &operands[0];
    let op2 = &operands[1];

    if !is_register_named(op1, "HL") {
        return None;
    }

    if operand_class(op2) != OperandClass::Reg16 {
        return None;
    }

    let reg = map_reg16(op2)?;
    Some(("DAD".to_string(), vec![reg]))
}

fn map_indirect_load(operands: &[FamilyOperand]) -> Option<Vec<FamilyOperand>> {
    if operands.len() != 2 {
        return None;
    }

    if !is_register_named(&operands[0], "A") {
        return None;
    }

    map_indirect_regpair(&operands[1]).map(|reg| vec![reg])
}

fn map_indirect_store(operands: &[FamilyOperand]) -> Option<Vec<FamilyOperand>> {
    if operands.len() != 2 {
        return None;
    }

    if !is_register_named(&operands[1], "A") {
        return None;
    }

    map_indirect_regpair(&operands[0]).map(|reg| vec![reg])
}

fn apply_condition_suffix(prefix: &str, operands: &[FamilyOperand]) -> Option<String> {
    let condition = operands.iter().find_map(|op| match op {
        FamilyOperand::Condition(name, _) => map_condition(name),
        FamilyOperand::Register(name, _) => map_condition(name),
        _ => None,
    })?;

    Some(format!("{prefix}{condition}"))
}

fn operand_class(operand: &FamilyOperand) -> OperandClass {
    match operand {
        FamilyOperand::Register(name, _) => classify_operand(name),
        FamilyOperand::Condition(name, _) => classify_operand(name),
        FamilyOperand::Indirect(name, _) => classify_operand(&format!("({name})")),
        FamilyOperand::Immediate(_) => OperandClass::Imm16,
        FamilyOperand::Indexed { .. } => OperandClass::Z80Only,
        FamilyOperand::RstVector(_)
        | FamilyOperand::InterruptMode(_)
        | FamilyOperand::BitNumber(_)
        | FamilyOperand::Port(_) => OperandClass::Imm16,
    }
}

fn map_operand_register(operand: &FamilyOperand) -> Option<FamilyOperand> {
    match operand {
        FamilyOperand::Register(name, span) => map_register(name)
            .map(|mapped| FamilyOperand::Register(mapped.to_string(), *span))
            .or_else(|| {
                map_condition(name)
                    .map(|mapped| FamilyOperand::Condition(mapped.to_string(), *span))
            }),
        FamilyOperand::Condition(name, span) => {
            map_condition(name).map(|mapped| FamilyOperand::Condition(mapped.to_string(), *span))
        }
        FamilyOperand::Indirect(name, span) => {
            if name.eq_ignore_ascii_case("HL") {
                Some(FamilyOperand::Register("M".to_string(), *span))
            } else {
                map_register(name).map(|mapped| FamilyOperand::Register(mapped.to_string(), *span))
            }
        }
        _ => None,
    }
}

fn map_reg8_or_mem(operand: &FamilyOperand) -> Option<FamilyOperand> {
    match operand {
        FamilyOperand::Register(name, span) => {
            map_register(name).map(|mapped| FamilyOperand::Register(mapped.to_string(), *span))
        }
        FamilyOperand::Indirect(name, span) => {
            if name.eq_ignore_ascii_case("HL") {
                Some(FamilyOperand::Register("M".to_string(), *span))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn map_reg16(operand: &FamilyOperand) -> Option<FamilyOperand> {
    match operand {
        FamilyOperand::Register(name, span) => {
            map_register(name).map(|mapped| FamilyOperand::Register(mapped.to_string(), *span))
        }
        _ => None,
    }
}

fn map_indirect_regpair(operand: &FamilyOperand) -> Option<FamilyOperand> {
    match operand {
        FamilyOperand::Indirect(name, span) => {
            map_register(name).map(|mapped| FamilyOperand::Register(mapped.to_string(), *span))
        }
        _ => None,
    }
}

fn immediate_expr(operand: &FamilyOperand) -> Option<Expr> {
    match operand {
        FamilyOperand::Immediate(expr) => Some(expr.clone()),
        _ => None,
    }
}

fn immediate_indirect_expr(operand: &FamilyOperand) -> Option<Expr> {
    match operand {
        FamilyOperand::Immediate(Expr::Indirect(inner, _)) => Some((**inner).clone()),
        _ => None,
    }
}

fn is_register_like(operand: &FamilyOperand) -> bool {
    matches!(
        operand,
        FamilyOperand::Register(_, _)
            | FamilyOperand::Indirect(_, _)
            | FamilyOperand::Condition(_, _)
    )
}

fn is_register_named(operand: &FamilyOperand, name: &str) -> bool {
    match operand {
        FamilyOperand::Register(reg, _) => reg.eq_ignore_ascii_case(name),
        _ => false,
    }
}

fn is_indirect_named(operand: &FamilyOperand, name: &str) -> bool {
    match operand {
        FamilyOperand::Indirect(reg, _) => reg.eq_ignore_ascii_case(name),
        _ => false,
    }
}

fn is_sp_hl_pair(op1: &FamilyOperand, op2: &FamilyOperand) -> bool {
    is_register_named(op1, "SP") && is_register_named(op2, "HL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_mapping() {
        assert_eq!(map_register("A"), Some("A"));
        assert_eq!(map_register("BC"), Some("B"));
        assert_eq!(map_register("DE"), Some("D"));
        assert_eq!(map_register("HL"), Some("H"));
        assert_eq!(map_register("AF"), Some("PSW"));
        assert_eq!(map_register("(HL)"), Some("M"));
        assert_eq!(map_register("M"), Some("M"));
        assert_eq!(map_register("IX"), None);
        assert_eq!(map_register("IY"), None);
    }

    #[test]
    fn test_find_mapping_ld() {
        // LD r,r' → MOV
        let entry = find_mapping("LD", 2, false);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "MOV");

        // LD r,n → MVI
        let entry = find_mapping("LD", 1, true);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "MVI");
    }

    #[test]
    fn test_find_mapping_jp() {
        // JP nn → JMP
        let entry = find_mapping("JP", 0, true);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "JMP");

        // JP cc,nn → Jcc
        let entry = find_mapping("JP", 1, true);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "J");
        assert_eq!(entry.unwrap().transform, OperandTransform::ConditionSuffix);
    }

    #[test]
    fn test_find_mapping_arithmetic() {
        // ADD A,r → ADD (drop first)
        let entry = find_mapping("ADD", 2, false);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "ADD");
        assert_eq!(entry.unwrap().transform, OperandTransform::DropFirst);

        // ADD A,n → ADI
        let entry = find_mapping("ADD", 1, true);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().canonical, "ADI");
    }

    #[test]
    fn test_z80_only_mnemonics() {
        assert!(is_z80_only_mnemonic("JR"));
        assert!(is_z80_only_mnemonic("DJNZ"));
        assert!(is_z80_only_mnemonic("LDIR"));
        assert!(is_z80_only_mnemonic("BIT"));
        assert!(!is_z80_only_mnemonic("LD"));
        assert!(!is_z80_only_mnemonic("ADD"));
        assert!(!is_z80_only_mnemonic("MOV"));
    }
}
