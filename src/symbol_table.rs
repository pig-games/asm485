// Symbol table for labels and constants.

use std::io::{self, Write};

#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    pub name: String,
    pub val: u32,
    pub rw: bool,
    pub updated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolTableResult {
    Ok,
    Duplicate,
    NotFound,
    TableFull,
}

pub const MAX_ENTRIES: usize = 66000;
pub const NO_ENTRY: u32 = 0x10000;

#[derive(Debug, Default)]
pub struct SymbolTable {
    entries: Vec<SymbolTableEntry>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, val: u32, rw: bool) -> SymbolTableResult {
        if self.entries.len() >= MAX_ENTRIES {
            return SymbolTableResult::TableFull;
        }

        for entry in &mut self.entries {
            if entry.name.eq_ignore_ascii_case(name) {
                if entry.rw {
                    entry.val = val;
                    return SymbolTableResult::Ok;
                }
                return SymbolTableResult::Duplicate;
            }
        }

        self.entries.push(SymbolTableEntry {
            name: name.to_string(),
            val,
            rw,
            updated: false,
        });
        SymbolTableResult::Ok
    }

    pub fn update(&mut self, name: &str, val: u32) -> SymbolTableResult {
        for entry in &mut self.entries {
            if entry.name.eq_ignore_ascii_case(name) {
                if entry.rw || !entry.updated {
                    entry.val = val;
                    entry.updated = true;
                    return SymbolTableResult::Ok;
                }
                return SymbolTableResult::Duplicate;
            }
        }

        SymbolTableResult::NotFound
    }

    pub fn lookup(&self, name: &str) -> u32 {
        for entry in &self.entries {
            if entry.name.eq_ignore_ascii_case(name) {
                return entry.val;
            }
        }
        NO_ENTRY
    }

    pub fn entry(&self, name: &str) -> Option<&SymbolTableEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    pub fn entry_mut(&mut self, name: &str) -> Option<&mut SymbolTableEntry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
    }

    pub fn dump<W: Write>(&self, mut out: W) -> io::Result<()> {
        for entry in &self.entries {
            writeln!(
                out,
                "{:<16}: {:04x} ({})",
                entry.name, entry.val, entry.val
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SymbolTable, SymbolTableResult, NO_ENTRY};

    #[test]
    fn add_and_lookup_are_case_insensitive() {
        let mut table = SymbolTable::new();
        assert_eq!(table.add("Foo", 0x10, false), SymbolTableResult::Ok);
        assert_eq!(table.lookup("foo"), 0x10);
        assert_eq!(table.lookup("FOO"), 0x10);
    }

    #[test]
    fn duplicate_and_rw_behavior() {
        let mut table = SymbolTable::new();
        assert_eq!(table.add("Val", 1, false), SymbolTableResult::Ok);
        assert_eq!(table.add("val", 2, false), SymbolTableResult::Duplicate);

        assert_eq!(table.add("Rw", 3, true), SymbolTableResult::Ok);
        assert_eq!(table.add("rw", 4, true), SymbolTableResult::Ok);
        assert_eq!(table.lookup("RW"), 4);
    }

    #[test]
    fn update_rules() {
        let mut table = SymbolTable::new();
        assert_eq!(table.update("missing", 1), SymbolTableResult::NotFound);
        assert_eq!(table.add("Once", 1, false), SymbolTableResult::Ok);
        assert_eq!(table.update("once", 2), SymbolTableResult::Ok);
        assert_eq!(table.update("ONCE", 3), SymbolTableResult::Duplicate);
        assert_eq!(table.lookup("once"), 2);

        assert_eq!(table.lookup("nope"), NO_ENTRY);
    }
}
