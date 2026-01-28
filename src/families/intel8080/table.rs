// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Instruction table for Intel 8080 family.
//!
//! This table contains the canonical Intel 8080 instruction set using Intel mnemonics.
//! CPU-specific instructions are in extension tables (see `extensions.rs`):
//! - 8085: RIM, SIM
//! - Z80: JR, DJNZ, block ops, bit ops, index registers, etc.
//!
//! Zilog dialect mnemonics are mapped to these canonical forms via `dialect.rs`.

/// Argument type for instruction encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgType {
    /// No additional argument
    None,
    /// 8-bit immediate or port
    Byte,
    /// 16-bit immediate or address
    Word,
    /// 8-bit relative offset for JR/DJNZ (Z80 extensions)
    Relative,
    /// Interrupt mode (0, 1, 2) for IM instruction (Z80)
    Im,
}

/// Prefix bytes for extended instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// No prefix (single-byte opcode)
    None,
    /// CB prefix (Z80 bit operations)
    Cb,
    /// DD prefix (Z80 IX operations)
    Dd,
    /// ED prefix (Z80 extended operations)
    Ed,
    /// FD prefix (Z80 IY operations)
    Fd,
    /// DD CB prefix (Z80 IX bit operations)
    DdCb,
    /// FD CB prefix (Z80 IY bit operations)
    FdCb,
}

/// Instruction table entry.
#[derive(Clone, Copy, Debug)]
pub struct InstructionEntry {
    pub mnemonic: &'static str,
    pub reg1: &'static str,
    pub reg2: &'static str,
    pub num_regs: u8,
    pub prefix: Prefix,
    pub opcode: u8,
    pub arg_type: ArgType,
}

/// Lookup an instruction by mnemonic and register operands.
pub fn lookup_instruction(mnemonic: &str, reg1: Option<&str>, reg2: Option<&str>) -> Option<&'static InstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    
    for entry in FAMILY_INSTRUCTION_TABLE {
        if !entry.mnemonic.eq_ignore_ascii_case(&upper) {
            continue;
        }
        
        // Match register operands
        let reg1_matches = match (entry.num_regs, reg1) {
            (0, None) => true,
            (0, Some(_)) => false,  // No regs expected but got one
            (1, Some(r)) => entry.reg1.eq_ignore_ascii_case(r),
            (1, None) => false,
            (2, Some(r)) => entry.reg1.eq_ignore_ascii_case(r),
            (2, None) => false,
            _ => false,
        };
        
        if !reg1_matches {
            continue;
        }
        
        let reg2_matches = match (entry.num_regs, reg2) {
            (0, _) | (1, _) => true, // No second reg expected
            (2, Some(r)) => entry.reg2.eq_ignore_ascii_case(r),
            (2, None) => false,
            _ => false,
        };
        
        if reg2_matches {
            return Some(entry);
        }
    }
    
    None
}

/// Check if a mnemonic exists in the family table.
pub fn has_mnemonic(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    FAMILY_INSTRUCTION_TABLE.iter().any(|e| e.mnemonic.eq_ignore_ascii_case(&upper))
}

/// Intel 8080 family instruction table.
/// 
/// This includes all 8080 instructions. 8085-specific instructions (RIM, SIM)
/// are handled by the I8085 CPU handler.
pub static FAMILY_INSTRUCTION_TABLE: &[InstructionEntry] = &[
    InstructionEntry { mnemonic: "ACI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xce, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "ADC", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x88, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x89, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x8e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x87, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x80, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x81, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x82, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x83, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x84, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x85, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x86, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc6, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "ANA", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa2, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa3, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa4, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANA", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa6, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ANI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe6, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "CALL", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xcd, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xdc, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CM", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xfc, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CMA", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x2f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x3f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xbf, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xba, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xbb, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xbc, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xbd, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CMP", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xbe, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CNC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd4, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CNZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc4, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CP", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf4, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CPE", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xec, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CPI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xfe, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "CPO", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe4, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "CZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xcc, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "DAA", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x27, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DAD", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x09, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DAD", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x19, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DAD", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x29, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DAD", reg1: "SP", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x39, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x3d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x05, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x0d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x15, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x1d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x25, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x2d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCR", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x35, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCX", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x0b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCX", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x1b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCX", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x2b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DCX", reg1: "SP", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x3b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf3, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "EI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xfb, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "HLT", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x76, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xdb, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "INR", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x3c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x04, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x0c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x14, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x1c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x24, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x2c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INR", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x34, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INX", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x03, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INX", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x13, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INX", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x23, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INX", reg1: "SP", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x33, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "JC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xda, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JM", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xfa, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JMP", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc3, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JNC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd2, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JNZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc2, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JP", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf2, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JPE", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xea, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JPO", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe2, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "JZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xca, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LDA", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x3a, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LDAX", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x0a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LDAX", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x1a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LHLD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x2a, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LXI", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x01, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LXI", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x11, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LXI", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x21, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LXI", reg1: "SP", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x31, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x7f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x78, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x79, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x7a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x7b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x7c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x7d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "A", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x7e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x47, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x40, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x41, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x42, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x43, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x44, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x45, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "B", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x46, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x4f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x48, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x49, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x4a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x4b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x4c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x4d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "C", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x4e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x57, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x50, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x51, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x52, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x53, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x54, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x55, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "D", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x56, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x5f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x58, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x59, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x5a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x5b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x5c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x5d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "E", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x5e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x67, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x60, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x61, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x62, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x63, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x64, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x65, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "H", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x66, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x6f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x68, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x69, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x6a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x6b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x6c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x6d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "L", reg2: "M", num_regs: 2, prefix: Prefix::None, opcode: 0x6e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "A", num_regs: 2, prefix: Prefix::None, opcode: 0x77, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "B", num_regs: 2, prefix: Prefix::None, opcode: 0x70, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "C", num_regs: 2, prefix: Prefix::None, opcode: 0x71, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "D", num_regs: 2, prefix: Prefix::None, opcode: 0x72, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "E", num_regs: 2, prefix: Prefix::None, opcode: 0x73, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "H", num_regs: 2, prefix: Prefix::None, opcode: 0x74, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MOV", reg1: "M", reg2: "L", num_regs: 2, prefix: Prefix::None, opcode: 0x75, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "MVI", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x3e, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x06, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x0e, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x16, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x1e, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x26, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x2e, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "MVI", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x36, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "NOP", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x00, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb2, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb3, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb4, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORA", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xb6, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ORI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf6, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "OUT", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd3, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "PCHL", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "POP", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xc1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "POP", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xd1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "POP", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xe1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "POP", reg1: "PSW", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xf1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xc5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xd5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xe5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "PSW", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xf5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RAL", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x17, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RAR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x1f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RET", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RLC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x07, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RM", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RNC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RNZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RP", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RPE", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RPO", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RRC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x0f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "0", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xc7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "1", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xcf, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "2", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xd7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "3", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xdf, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "4", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xe7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "5", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xef, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "6", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xf7, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RST", reg1: "7", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xff, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xc8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9f, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x98, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x99, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9a, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9b, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9c, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9d, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBB", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x9e, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xde, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "SHLD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x22, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "SPHL", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xf9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "STA", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x32, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "STAX", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x02, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "STAX", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x12, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "STC", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x37, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x97, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x90, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x91, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x92, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x93, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x94, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x95, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUB", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x96, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SUI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xd6, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "XCHG", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xeb, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "A", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xaf, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "B", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xa9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "D", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xaa, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "E", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xab, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "H", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xac, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "L", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xad, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRA", reg1: "M", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0xae, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "XRI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xee, arg_type: ArgType::Byte },
    InstructionEntry { mnemonic: "XTHL", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xe3, arg_type: ArgType::None },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_nop() {
        let entry = lookup_instruction("NOP", None, None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x00);
    }

    #[test]
    fn lookup_mov_a_b() {
        let entry = lookup_instruction("MOV", Some("A"), Some("B"));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x78);
    }

    #[test]
    fn lookup_mvi_a() {
        let entry = lookup_instruction("MVI", Some("A"), None);
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.opcode, 0x3e);
        assert_eq!(e.arg_type, ArgType::Byte);
    }

    #[test]
    fn lookup_lxi_h() {
        let entry = lookup_instruction("LXI", Some("H"), None);
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.opcode, 0x21);
        assert_eq!(e.arg_type, ArgType::Word);
    }

    #[test]
    fn has_mnemonic_works() {
        assert!(has_mnemonic("MOV"));
        assert!(has_mnemonic("mov"));
        assert!(has_mnemonic("NOP"));
        assert!(!has_mnemonic("LD")); // Z80 mnemonic, not in 8080 table
    }
}
