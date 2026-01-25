// Instruction metadata types shared by opcode table.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgType {
    None,
    Byte,
    Word,
}

pub struct InstructionEntry {
    pub mnemonic: &'static str,
    pub reg1: &'static str,
    pub reg2: &'static str,
    pub num_regs: u8,
    pub opcode: u8,
    pub arg_type: ArgType,
}

pub mod table;

#[cfg(test)]
mod tests {
    use super::table::INSTRUCTION_TABLE;

    #[test]
    fn instruction_table_is_sorted_by_mnemonic() {
        let mut prev = "";
        for entry in INSTRUCTION_TABLE {
            let current = entry.mnemonic.to_ascii_uppercase();
            let prev_upper = prev.to_ascii_uppercase();
            assert!(
                current >= prev_upper,
                "instruction table out of order: {} before {}",
                prev,
                entry.mnemonic
            );
            prev = entry.mnemonic;
        }
    }
}
