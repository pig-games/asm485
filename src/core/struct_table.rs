// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Struct definition table for assembly-time layout metadata.

use std::collections::HashMap;

use crate::core::asm_value::StructDef;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StructTableError {
    Duplicate(String),
}

#[derive(Clone, Debug, Default)]
pub struct StructTable {
    defs: HashMap<String, StructDef>,
}

impl StructTable {
    pub fn new() -> Self {
        Self {
            defs: HashMap::new(),
        }
    }

    pub fn register(&mut self, def: StructDef) -> Result<(), StructTableError> {
        let key = canonical_key(def.name.as_str());
        if self.defs.contains_key(&key) {
            return Err(StructTableError::Duplicate(def.name));
        }
        self.defs.insert(key, def);
        Ok(())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.defs.contains_key(&canonical_key(name))
    }

    pub fn get(&self, name: &str) -> Option<&StructDef> {
        self.defs.get(&canonical_key(name))
    }

    pub fn clear(&mut self) {
        self.defs.clear();
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }
}

fn canonical_key(name: &str) -> String {
    name.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::{StructTable, StructTableError};
    use crate::core::asm_value::{StructDef, StructField};

    fn make_struct(name: &str) -> StructDef {
        StructDef {
            name: name.to_string(),
            fields: vec![
                StructField {
                    name: "x".to_string(),
                    offset: 0,
                    size: 1,
                },
                StructField {
                    name: "y".to_string(),
                    offset: 1,
                    size: 1,
                },
            ],
            size: 2,
        }
    }

    #[test]
    fn register_and_lookup_is_case_insensitive() {
        let mut table = StructTable::new();
        table
            .register(make_struct("Sprite"))
            .expect("first definition should register");
        assert!(table.contains("sprite"));
        assert!(table.contains("SPRITE"));
        let def = table.get("sPrItE").expect("definition should be found");
        assert_eq!(def.size, 2);
        assert_eq!(def.fields.len(), 2);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut table = StructTable::new();
        table
            .register(make_struct("Sprite"))
            .expect("first definition should register");
        let err = table
            .register(make_struct("sprite"))
            .expect_err("duplicate names should fail");
        assert_eq!(err, StructTableError::Duplicate("sprite".to_string()));
    }

    #[test]
    fn clear_resets_state() {
        let mut table = StructTable::new();
        table
            .register(make_struct("Sprite"))
            .expect("definition should register");
        assert_eq!(table.len(), 1);
        table.clear();
        assert!(table.is_empty());
        assert!(!table.contains("Sprite"));
    }
}
