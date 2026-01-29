// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Module registry for CPU families, CPUs, and syntax dialects.
//!
//! The registry is intentionally generic and has no knowledge of concrete
//! families or CPUs. Family and CPU modules provide type-erased handlers and
//! operand containers that keep instruction tables and concrete operand types
//! private to their modules.

use std::any::Any;
use std::collections::HashMap;

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::{AssemblerContext, EncodeResult, FamilyParseError};
use crate::core::parser::Expr;

pub trait FamilyOperandSet: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn FamilyOperandSet>;
}

impl Clone for Box<dyn FamilyOperandSet> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait OperandSet: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn OperandSet>;
}

impl Clone for Box<dyn OperandSet> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait FamilyHandlerDyn: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError>;
    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>>;
    fn is_register(&self, name: &str) -> bool;
    fn is_condition(&self, name: &str) -> bool;
    fn supports_rst(&self) -> bool {
        false
    }
}

pub trait CpuHandlerDyn: Send + Sync {
    fn cpu_id(&self) -> CpuType;
    fn family_id(&self) -> CpuFamily;
    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &dyn FamilyOperandSet,
        ctx: &dyn AssemblerContext,
    ) -> Result<Box<dyn OperandSet>, String>;
    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>>;
    fn supports_mnemonic(&self, mnemonic: &str) -> bool;
}

pub trait DialectModule: Send + Sync {
    fn dialect_id(&self) -> &'static str;
    fn family_id(&self) -> CpuFamily;
    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)>;
}

pub trait CpuValidator: Send + Sync {
    fn validate_instruction(
        &self,
        _mnemonic: &str,
        _operands: &dyn OperandSet,
        _ctx: &dyn AssemblerContext,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub trait FamilyModule: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn canonical_dialect(&self) -> &'static str;
    fn dialects(&self) -> Vec<Box<dyn DialectModule>>;
    fn handler(&self) -> Box<dyn FamilyHandlerDyn>;
}

pub trait CpuModule: Send + Sync {
    fn cpu_id(&self) -> CpuType;
    fn family_id(&self) -> CpuFamily;
    fn cpu_names(&self) -> &'static [&'static str];
    fn cpu_display_name(&self) -> &'static str {
        self.cpu_names()
            .first()
            .copied()
            .unwrap_or_else(|| self.cpu_id().as_str())
    }
    fn default_dialect(&self) -> &'static str;
    fn handler(&self) -> Box<dyn CpuHandlerDyn>;
    fn validator(&self) -> Option<Box<dyn CpuValidator>> {
        None
    }
}

#[derive(Debug, Clone)]
pub enum RegistryError {
    MissingFamily(CpuFamily),
    MissingCpu(CpuType),
    MissingDialect { family: CpuFamily, dialect: String },
}

pub struct ResolvedPipeline<'a> {
    pub family: Box<dyn FamilyHandlerDyn>,
    pub cpu: Box<dyn CpuHandlerDyn>,
    pub dialect: &'a dyn DialectModule,
    pub validator: Option<Box<dyn CpuValidator>>,
}

pub struct ModuleRegistry {
    families: HashMap<CpuFamily, Box<dyn FamilyModule>>,
    cpus: HashMap<CpuType, Box<dyn CpuModule>>,
    dialects: HashMap<(CpuFamily, String), Box<dyn DialectModule>>,
    cpu_names: HashMap<String, CpuType>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            families: HashMap::new(),
            cpus: HashMap::new(),
            dialects: HashMap::new(),
            cpu_names: HashMap::new(),
        }
    }

    pub fn register_family(&mut self, module: Box<dyn FamilyModule>) {
        let family_id = module.family_id();
        for dialect in module.dialects() {
            let key = (family_id, normalize_dialect(dialect.dialect_id()));
            self.dialects.insert(key, dialect);
        }
        self.families.insert(family_id, module);
    }

    pub fn register_cpu(&mut self, module: Box<dyn CpuModule>) {
        let cpu_id = module.cpu_id();
        for name in module.cpu_names() {
            self.cpu_names
                .insert(normalize_cpu_name(name), cpu_id);
        }
        self.cpus.insert(cpu_id, module);
    }

    pub fn resolve_cpu_name(&self, name: &str) -> Option<CpuType> {
        self.cpu_names
            .get(&normalize_cpu_name(name))
            .copied()
    }

    pub fn cpu_display_name(&self, cpu: CpuType) -> Option<&'static str> {
        self.cpus.get(&cpu).map(|module| module.cpu_display_name())
    }

    pub fn cpu_name_list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.cpu_names.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn resolve_pipeline(
        &self,
        cpu: CpuType,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedPipeline<'_>, RegistryError> {
        let cpu_module = self
            .cpus
            .get(&cpu)
            .ok_or(RegistryError::MissingCpu(cpu))?;
        let family_id = cpu_module.family_id();
        let family_module = self
            .families
            .get(&family_id)
            .ok_or(RegistryError::MissingFamily(family_id))?;

        let selected = if let Some(override_id) = dialect_override {
            self.lookup_dialect(family_id, override_id)
                .ok_or_else(|| RegistryError::MissingDialect {
                    family: family_id,
                    dialect: override_id.to_string(),
                })?
        } else if let Some(dialect) =
            self.lookup_dialect(family_id, cpu_module.default_dialect())
        {
            dialect
        } else {
            self.lookup_dialect(family_id, family_module.canonical_dialect())
                .ok_or_else(|| RegistryError::MissingDialect {
                    family: family_id,
                    dialect: family_module.canonical_dialect().to_string(),
                })?
        };

        Ok(ResolvedPipeline {
            family: family_module.handler(),
            cpu: cpu_module.handler(),
            dialect: selected,
            validator: cpu_module.validator(),
        })
    }

    fn lookup_dialect(
        &self,
        family: CpuFamily,
        dialect: &str,
    ) -> Option<&dyn DialectModule> {
        let key = (family, normalize_dialect(dialect));
        self.dialects.get(&key).map(|dialect| dialect.as_ref())
    }
}

fn normalize_dialect(dialect: &str) -> String {
    dialect.to_ascii_lowercase()
}

fn normalize_cpu_name(name: &str) -> String {
    name.to_ascii_lowercase()
}
