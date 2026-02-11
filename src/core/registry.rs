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
use crate::core::family::{AssemblerContext, EncodeResult, FamilyEncodeResult, FamilyParseError};
use crate::core::parser::Expr;

/// Type-erased container for family-level operand sets.
///
/// Implementations wrap a concrete operand type and provide downcasting
/// via `Any` so that the CPU handler can recover the concrete type.
pub trait FamilyOperandSet: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn FamilyOperandSet>;
}

impl Clone for Box<dyn FamilyOperandSet> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Type-erased container for CPU-resolved operand sets.
pub trait OperandSet: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn OperandSet>;
}

impl Clone for Box<dyn OperandSet> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Type-erased family instruction handler.
///
/// Owns the family operand parsing logic and base instruction tables.
pub trait FamilyHandlerDyn: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError>;
    fn encode_family_operands(
        &self,
        canonical_mnemonic: &str,
        display_mnemonic: &str,
        operands: &dyn FamilyOperandSet,
        ctx: &dyn AssemblerContext,
    ) -> FamilyEncodeResult<Vec<u8>> {
        let _ = (canonical_mnemonic, display_mnemonic, operands, ctx);
        FamilyEncodeResult::NotFound
    }
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

/// Type-erased CPU-specific instruction handler.
///
/// Resolves family operands into CPU operands and encodes CPU-extension
/// instructions not covered by the family handler.
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
    fn max_program_address(&self) -> u32 {
        0xFFFF
    }
    fn native_word_size_bytes(&self) -> u32 {
        2
    }
    fn is_little_endian(&self) -> bool {
        true
    }
    fn runtime_state_defaults(&self) -> HashMap<String, u32> {
        HashMap::new()
    }
    fn update_runtime_state_after_encode(
        &self,
        _mnemonic: &str,
        _operands: &dyn OperandSet,
        _state: &mut HashMap<String, u32>,
    ) {
    }
    fn apply_runtime_directive(
        &self,
        _directive: &str,
        _operands: &[Expr],
        _ctx: &dyn AssemblerContext,
        _state: &mut HashMap<String, u32>,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

/// Dialect mapping layer for alternate syntax (e.g. Z80 mnemonics → Intel 8080).
pub trait DialectModule: Send + Sync {
    fn dialect_id(&self) -> &'static str;
    fn family_id(&self) -> CpuFamily;
    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)>;
}

/// Optional CPU-level instruction validator (e.g. 8085 undocumented warnings).
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

/// Registration interface for a CPU family (provides handler factory and dialects).
pub trait FamilyModule: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn family_cpu_id(&self) -> Option<CpuType> {
        None
    }
    fn family_cpu_name(&self) -> Option<&'static str> {
        None
    }
    fn cpu_names(&self, registry: &ModuleRegistry) -> Vec<String> {
        registry.family_cpu_names(self.family_id())
    }
    fn canonical_dialect(&self) -> &'static str;
    fn dialects(&self) -> Vec<Box<dyn DialectModule>>;
    fn handler(&self) -> Box<dyn FamilyHandlerDyn>;
}

/// Registration interface for a specific CPU (provides handler factory and defaults).
pub trait CpuModule: Send + Sync {
    fn cpu_id(&self) -> CpuType;
    fn family_id(&self) -> CpuFamily;
    fn cpu_name(&self) -> &'static str;
    fn cpu_aliases(&self) -> &'static [&'static str] {
        &[]
    }
    fn default_dialect(&self) -> &'static str;
    fn handler(&self) -> Box<dyn CpuHandlerDyn>;
    fn validator(&self) -> Option<Box<dyn CpuValidator>> {
        None
    }
}

/// Error returned when the registry cannot resolve a requested pipeline.
#[derive(Debug, Clone)]
pub enum RegistryError {
    MissingFamily(CpuFamily),
    MissingCpu(CpuType),
    MissingDialect { family: CpuFamily, dialect: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFamily(fam) => write!(f, "no handler registered for family {:?}", fam),
            Self::MissingCpu(cpu) => write!(f, "no handler registered for CPU {:?}", cpu),
            Self::MissingDialect { family, dialect } => {
                write!(
                    f,
                    "no dialect '{}' registered for family {:?}",
                    dialect, family
                )
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// A fully-resolved assembly pipeline: family handler + CPU handler + dialect + validator.
pub struct ResolvedPipeline<'a> {
    pub family: Box<dyn FamilyHandlerDyn>,
    pub cpu: Box<dyn CpuHandlerDyn>,
    pub dialect: &'a dyn DialectModule,
    pub validator: Option<Box<dyn CpuValidator>>,
}

/// Central registry mapping CPU families, CPU types, and dialect modules.
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
        if let (Some(cpu_id), Some(cpu_name)) = (module.family_cpu_id(), module.family_cpu_name()) {
            self.cpu_names.insert(normalize_cpu_name(cpu_name), cpu_id);
        }
        self.families.insert(family_id, module);
    }

    pub fn register_cpu(&mut self, module: Box<dyn CpuModule>) {
        let cpu_id = module.cpu_id();
        self.cpu_names
            .insert(normalize_cpu_name(module.cpu_name()), cpu_id);
        for alias in module.cpu_aliases() {
            self.cpu_names.insert(normalize_cpu_name(alias), cpu_id);
        }
        self.cpus.insert(cpu_id, module);
    }

    pub fn resolve_cpu_name(&self, name: &str) -> Option<CpuType> {
        self.cpu_names.get(&normalize_cpu_name(name)).copied()
    }

    pub fn cpu_display_name(&self, cpu: CpuType) -> Option<&'static str> {
        self.cpus.get(&cpu).map(|module| module.cpu_name())
    }

    pub fn family_cpu_names(&self, family: CpuFamily) -> Vec<String> {
        let mut names: Vec<String> = self
            .cpus
            .values()
            .filter(|module| module.family_id() == family)
            .map(|module| module.cpu_name().to_string())
            .collect();

        if let Some(module) = self.families.get(&family) {
            if let Some(cpu_name) = module.family_cpu_name() {
                names.push(cpu_name.to_string());
            }
        }

        names.sort();
        names.dedup();
        names
    }

    pub fn cpu_names_for_family(&self, family: CpuFamily) -> Vec<String> {
        self.family_cpu_names(family)
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
        let cpu_module = self.cpus.get(&cpu).ok_or(RegistryError::MissingCpu(cpu))?;
        let family_id = cpu_module.family_id();
        let family_module = self
            .families
            .get(&family_id)
            .ok_or(RegistryError::MissingFamily(family_id))?;

        let selected = if let Some(override_id) = dialect_override {
            self.lookup_dialect(family_id, override_id).ok_or_else(|| {
                RegistryError::MissingDialect {
                    family: family_id,
                    dialect: override_id.to_string(),
                }
            })?
        } else if let Some(dialect) = self.lookup_dialect(family_id, cpu_module.default_dialect()) {
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

    fn lookup_dialect(&self, family: CpuFamily, dialect: &str) -> Option<&dyn DialectModule> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::cpu::{CpuFamily, CpuType};
    use crate::core::family::{AssemblerContext, EncodeResult, FamilyParseError};
    use crate::core::parser::Expr;
    use crate::core::symbol_table::SymbolTable;

    const TEST_FAMILY: CpuFamily = CpuFamily::new("test_family");
    const TEST_CPU: CpuType = CpuType::new("test_cpu");
    const OTHER_CPU: CpuType = CpuType::new("other_cpu");
    const TEST_RUNTIME_KEY: &str = "test.runtime";

    // --- Minimal stubs for testing ---

    struct StubFamilyOperandSet;
    impl FamilyOperandSet for StubFamilyOperandSet {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn clone_box(&self) -> Box<dyn FamilyOperandSet> {
            Box::new(StubFamilyOperandSet)
        }
    }

    struct StubOperandSet;
    impl OperandSet for StubOperandSet {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn clone_box(&self) -> Box<dyn OperandSet> {
            Box::new(StubOperandSet)
        }
    }

    struct StubFamilyHandler;
    impl FamilyHandlerDyn for StubFamilyHandler {
        fn family_id(&self) -> CpuFamily {
            TEST_FAMILY
        }
        fn parse_operands(
            &self,
            _mnemonic: &str,
            _exprs: &[Expr],
        ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError> {
            Ok(Box::new(StubFamilyOperandSet))
        }
        fn encode_instruction(
            &self,
            _mnemonic: &str,
            _operands: &dyn OperandSet,
            _ctx: &dyn AssemblerContext,
        ) -> EncodeResult<Vec<u8>> {
            EncodeResult::NotFound
        }
        fn is_register(&self, _name: &str) -> bool {
            false
        }
        fn is_condition(&self, _name: &str) -> bool {
            false
        }
    }

    struct StubCpuHandler;
    impl CpuHandlerDyn for StubCpuHandler {
        fn cpu_id(&self) -> CpuType {
            TEST_CPU
        }
        fn family_id(&self) -> CpuFamily {
            TEST_FAMILY
        }
        fn resolve_operands(
            &self,
            _mnemonic: &str,
            _family_operands: &dyn FamilyOperandSet,
            _ctx: &dyn AssemblerContext,
        ) -> Result<Box<dyn OperandSet>, String> {
            Ok(Box::new(StubOperandSet))
        }
        fn encode_instruction(
            &self,
            _mnemonic: &str,
            _operands: &dyn OperandSet,
            _ctx: &dyn AssemblerContext,
        ) -> EncodeResult<Vec<u8>> {
            EncodeResult::NotFound
        }
        fn supports_mnemonic(&self, _mnemonic: &str) -> bool {
            false
        }
        fn native_word_size_bytes(&self) -> u32 {
            3
        }
        fn max_program_address(&self) -> u32 {
            0x01FF_FFFF
        }
        fn is_little_endian(&self) -> bool {
            false
        }
        fn runtime_state_defaults(&self) -> HashMap<String, u32> {
            let mut state = HashMap::new();
            state.insert(TEST_RUNTIME_KEY.to_string(), 7);
            state
        }
        fn update_runtime_state_after_encode(
            &self,
            mnemonic: &str,
            _operands: &dyn OperandSet,
            state: &mut HashMap<String, u32>,
        ) {
            if mnemonic.eq_ignore_ascii_case("PING") {
                state.insert(TEST_RUNTIME_KEY.to_string(), 9);
            }
        }
        fn apply_runtime_directive(
            &self,
            directive: &str,
            _operands: &[Expr],
            _ctx: &dyn AssemblerContext,
            state: &mut HashMap<String, u32>,
        ) -> Result<bool, String> {
            if directive.eq_ignore_ascii_case("STATE") {
                state.insert(TEST_RUNTIME_KEY.to_string(), 11);
                return Ok(true);
            }
            Ok(false)
        }
    }

    struct StubContext {
        symbols: SymbolTable,
    }

    impl StubContext {
        fn new() -> Self {
            Self {
                symbols: SymbolTable::new(),
            }
        }
    }

    impl AssemblerContext for StubContext {
        fn eval_expr(&self, _expr: &Expr) -> Result<i64, String> {
            Ok(0)
        }

        fn symbols(&self) -> &SymbolTable {
            &self.symbols
        }

        fn has_symbol(&self, _name: &str) -> bool {
            false
        }

        fn symbol_is_finalized(&self, _name: &str) -> Option<bool> {
            None
        }

        fn current_address(&self) -> u32 {
            0
        }

        fn pass(&self) -> u8 {
            1
        }
    }

    struct StubDialect;
    impl DialectModule for StubDialect {
        fn dialect_id(&self) -> &'static str {
            "test_dialect"
        }
        fn family_id(&self) -> CpuFamily {
            TEST_FAMILY
        }
        fn map_mnemonic(
            &self,
            _mnemonic: &str,
            _operands: &dyn FamilyOperandSet,
        ) -> Option<(String, Box<dyn FamilyOperandSet>)> {
            None
        }
    }

    struct StubFamilyModule;
    impl FamilyModule for StubFamilyModule {
        fn family_id(&self) -> CpuFamily {
            TEST_FAMILY
        }
        fn canonical_dialect(&self) -> &'static str {
            "test_dialect"
        }
        fn dialects(&self) -> Vec<Box<dyn DialectModule>> {
            vec![Box::new(StubDialect)]
        }
        fn handler(&self) -> Box<dyn FamilyHandlerDyn> {
            Box::new(StubFamilyHandler)
        }
    }

    struct StubCpuModule;
    impl CpuModule for StubCpuModule {
        fn cpu_id(&self) -> CpuType {
            TEST_CPU
        }
        fn family_id(&self) -> CpuFamily {
            TEST_FAMILY
        }
        fn cpu_name(&self) -> &'static str {
            "TestCpu"
        }
        fn cpu_aliases(&self) -> &'static [&'static str] {
            &["test_alias", "test16"]
        }
        fn default_dialect(&self) -> &'static str {
            "test_dialect"
        }
        fn handler(&self) -> Box<dyn CpuHandlerDyn> {
            Box::new(StubCpuHandler)
        }
    }

    #[test]
    fn register_and_resolve_cpu_name() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        assert_eq!(reg.resolve_cpu_name("testcpu"), Some(TEST_CPU));
        assert!(reg.resolve_cpu_name("nonexistent").is_none());
    }

    #[test]
    fn resolve_cpu_name_is_case_insensitive() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        assert_eq!(reg.resolve_cpu_name("TESTCPU"), Some(TEST_CPU));
        assert_eq!(reg.resolve_cpu_name("TestCpu"), Some(TEST_CPU));
        assert_eq!(reg.resolve_cpu_name("testcpu"), Some(TEST_CPU));
    }

    #[test]
    fn resolve_cpu_alias_name_maps_to_cpu() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        assert_eq!(reg.resolve_cpu_name("test_alias"), Some(TEST_CPU));
        assert_eq!(reg.resolve_cpu_name("TEST16"), Some(TEST_CPU));
    }

    #[test]
    fn resolve_pipeline_succeeds() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        let pipeline = reg.resolve_pipeline(TEST_CPU, None);
        assert!(pipeline.is_ok());
        let p = pipeline.unwrap();
        assert_eq!(p.family.family_id(), TEST_FAMILY);
        assert_eq!(p.cpu.cpu_id(), TEST_CPU);
        assert_eq!(p.dialect.dialect_id(), "test_dialect");
    }

    #[test]
    fn pipeline_exposes_cpu_runtime_hooks() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        let p = reg.resolve_pipeline(TEST_CPU, None).expect("pipeline");
        assert_eq!(p.cpu.max_program_address(), 0x01FF_FFFF);
        assert_eq!(p.cpu.native_word_size_bytes(), 3);
        assert!(!p.cpu.is_little_endian());
        let mut state = p.cpu.runtime_state_defaults();
        assert_eq!(state.get(TEST_RUNTIME_KEY).copied(), Some(7));
        p.cpu
            .update_runtime_state_after_encode("PING", &StubOperandSet, &mut state);
        assert_eq!(state.get(TEST_RUNTIME_KEY).copied(), Some(9));
        let ctx = StubContext::new();
        let handled = p
            .cpu
            .apply_runtime_directive("STATE", &[], &ctx, &mut state)
            .expect("runtime directive");
        assert!(handled);
        assert_eq!(state.get(TEST_RUNTIME_KEY).copied(), Some(11));
    }

    #[test]
    fn resolve_pipeline_missing_cpu_returns_error() {
        let reg = ModuleRegistry::new();
        let result = reg.resolve_pipeline(TEST_CPU, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_pipeline_missing_dialect_returns_error() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        let result = reg.resolve_pipeline(TEST_CPU, Some("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn cpu_name_list_returns_registered_names() {
        let mut reg = ModuleRegistry::new();
        reg.register_family(Box::new(StubFamilyModule));
        reg.register_cpu(Box::new(StubCpuModule));

        let names = reg.cpu_name_list();
        assert!(names.contains(&"testcpu".to_string()));
    }

    #[test]
    fn cpu_display_name_returns_correct_name() {
        let mut reg = ModuleRegistry::new();
        reg.register_cpu(Box::new(StubCpuModule));

        assert_eq!(reg.cpu_display_name(TEST_CPU), Some("TestCpu"));
        assert_eq!(reg.cpu_display_name(OTHER_CPU), None);
    }

    #[test]
    fn registry_error_display() {
        let err = RegistryError::MissingCpu(TEST_CPU);
        assert!(err.to_string().contains("CPU"));
        let err = RegistryError::MissingFamily(TEST_FAMILY);
        assert!(err.to_string().contains("family"));
        let err = RegistryError::MissingDialect {
            family: TEST_FAMILY,
            dialect: "z80".to_string(),
        };
        assert!(err.to_string().contains("dialect"));
    }
}
