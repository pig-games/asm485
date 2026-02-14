// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Host/runtime bridge helpers for hierarchy-aware target selection.

use std::collections::{HashMap, HashSet};

use crate::core::registry::ModuleRegistry;
use crate::opthread::builder::{build_hierarchy_chunks_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
use crate::opthread::package::HierarchyChunks;

/// Errors emitted by the opThread host/runtime bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeBridgeError {
    ActiveCpuNotSet,
    Build(HierarchyBuildError),
    Hierarchy(HierarchyError),
}

impl std::fmt::Display for RuntimeBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveCpuNotSet => write!(f, "active cpu is not set"),
            Self::Build(err) => write!(f, "runtime model build error: {}", err),
            Self::Hierarchy(err) => write!(f, "hierarchy resolution error: {}", err),
        }
    }
}

impl std::error::Error for RuntimeBridgeError {}

impl From<HierarchyError> for RuntimeBridgeError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

impl From<HierarchyBuildError> for RuntimeBridgeError {
    fn from(value: HierarchyBuildError) -> Self {
        Self::Build(value)
    }
}

/// Small bridge state that mirrors host-side active target selection APIs.
#[derive(Debug)]
pub struct HierarchyRuntimeBridge {
    package: HierarchyPackage,
    active_cpu: Option<String>,
    dialect_override: Option<String>,
}

impl HierarchyRuntimeBridge {
    pub fn new(package: HierarchyPackage) -> Self {
        Self {
            package,
            active_cpu: None,
            dialect_override: None,
        }
    }

    pub fn active_cpu(&self) -> Option<&str> {
        self.active_cpu.as_deref()
    }

    pub fn dialect_override(&self) -> Option<&str> {
        self.dialect_override.as_deref()
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, self.dialect_override.as_deref())?;
        self.active_cpu = Some(cpu_id.to_string());
        Ok(())
    }

    pub fn set_dialect_override(
        &mut self,
        dialect_override: Option<&str>,
    ) -> Result<(), RuntimeBridgeError> {
        if let Some(cpu_id) = self.active_cpu.as_deref() {
            self.package.resolve_pipeline(cpu_id, dialect_override)?;
        }
        self.dialect_override = dialect_override.map(ToString::to_string);
        Ok(())
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, dialect_override)
            .map_err(Into::into)
    }

    pub fn resolve_active_pipeline(&self) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.resolve_pipeline(cpu_id, self.dialect_override.as_deref())
    }

    pub fn resolve_active_pipeline_context(
        &self,
    ) -> Result<ResolvedHierarchyContext<'_>, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.package
            .resolve_pipeline_context(cpu_id, self.dialect_override.as_deref())
            .map_err(Into::into)
    }
}

/// Runtime view with resolved hierarchy bridge and scoped FORM ownership sets.
#[derive(Debug)]
pub struct HierarchyExecutionModel {
    bridge: HierarchyRuntimeBridge,
    family_forms: HashMap<String, HashSet<String>>,
    cpu_forms: HashMap<String, HashSet<String>>,
    dialect_forms: HashMap<String, HashSet<String>>,
}

impl HierarchyExecutionModel {
    pub fn from_registry(registry: &ModuleRegistry) -> Result<Self, RuntimeBridgeError> {
        let chunks = build_hierarchy_chunks_from_registry(registry)?;
        Self::from_chunks(chunks)
    }

    pub fn from_chunks(chunks: HierarchyChunks) -> Result<Self, RuntimeBridgeError> {
        let package = HierarchyPackage::new(chunks.families, chunks.cpus, chunks.dialects)?;
        let mut family_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cpu_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut dialect_forms: HashMap<String, HashSet<String>> = HashMap::new();
        for form in chunks.forms {
            let mnemonic = form.mnemonic.to_ascii_lowercase();
            match form.owner {
                ScopedOwner::Family(owner) => {
                    family_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Cpu(owner) => {
                    cpu_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Dialect(owner) => {
                    dialect_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
            }
        }

        Ok(Self {
            bridge: HierarchyRuntimeBridge::new(package),
            family_forms,
            cpu_forms,
            dialect_forms,
        })
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.bridge.set_active_cpu(cpu_id)
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.bridge.resolve_pipeline(cpu_id, dialect_override)
    }

    pub fn supports_mnemonic(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
    ) -> Result<bool, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let needle = mnemonic.to_ascii_lowercase();

        if contains_form(&self.dialect_forms, &resolved.dialect_id, &needle) {
            return Ok(true);
        }
        if contains_form(&self.cpu_forms, &resolved.cpu_id, &needle) {
            return Ok(true);
        }
        Ok(contains_form(
            &self.family_forms,
            &resolved.family_id,
            &needle,
        ))
    }
}

fn contains_form(map: &HashMap<String, HashSet<String>>, owner_id: &str, mnemonic: &str) -> bool {
    map.get(&owner_id.to_ascii_lowercase())
        .is_some_and(|forms| forms.contains(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::ModuleRegistry;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::hierarchy::{CpuDescriptor, DialectDescriptor, FamilyDescriptor};

    fn sample_package() -> HierarchyPackage {
        HierarchyPackage::new(
            vec![
                FamilyDescriptor {
                    id: "intel8080".to_string(),
                    canonical_dialect: "intel".to_string(),
                },
                FamilyDescriptor {
                    id: "mos6502".to_string(),
                    canonical_dialect: "mos".to_string(),
                },
            ],
            vec![
                CpuDescriptor {
                    id: "8085".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("intel".to_string()),
                },
                CpuDescriptor {
                    id: "z80".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("zilog".to_string()),
                },
                CpuDescriptor {
                    id: "6502".to_string(),
                    family_id: "mos6502".to_string(),
                    default_dialect: Some("mos".to_string()),
                },
            ],
            vec![
                DialectDescriptor {
                    id: "intel".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: None,
                },
                DialectDescriptor {
                    id: "zilog".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: Some(vec!["z80".to_string()]),
                },
                DialectDescriptor {
                    id: "mos".to_string(),
                    family_id: "mos6502".to_string(),
                    cpu_allow_list: None,
                },
            ],
        )
        .expect("sample package should validate")
    }

    #[test]
    fn active_cpu_selection_and_resolution_work() {
        let mut bridge = HierarchyRuntimeBridge::new(sample_package());

        assert!(matches!(
            bridge.resolve_active_pipeline(),
            Err(RuntimeBridgeError::ActiveCpuNotSet)
        ));

        bridge.set_active_cpu("z80").expect("set active cpu");
        let resolved = bridge
            .resolve_active_pipeline()
            .expect("active cpu should resolve");
        assert_eq!(resolved.family_id, "intel8080");
        assert_eq!(resolved.dialect_id, "zilog");
    }

    #[test]
    fn explicit_resolve_pipeline_supports_override() {
        let bridge = HierarchyRuntimeBridge::new(sample_package());

        let resolved = bridge
            .resolve_pipeline("8085", Some("intel"))
            .expect("explicit resolve should succeed");
        assert_eq!(resolved.cpu_id, "8085");
        assert_eq!(resolved.dialect_id, "intel");
    }

    #[test]
    fn override_validation_uses_active_cpu_context() {
        let mut bridge = HierarchyRuntimeBridge::new(sample_package());
        bridge.set_active_cpu("8085").expect("set active cpu");

        let err = bridge
            .set_dialect_override(Some("zilog"))
            .expect_err("zilog should be blocked for 8085");
        assert!(matches!(
            err,
            RuntimeBridgeError::Hierarchy(HierarchyError::CpuBlockedByDialectAllowList { .. })
        ));

        bridge
            .set_dialect_override(Some("intel"))
            .expect("intel override should pass");
        assert_eq!(bridge.dialect_override(), Some("intel"));
    }

    #[test]
    fn execution_model_supports_family_and_cpu_forms() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        assert!(model
            .supports_mnemonic("m6502", None, "lda")
            .expect("resolve lda"));
        assert!(!model
            .supports_mnemonic("m6502", None, "bra")
            .expect("resolve bra"));
        assert!(model
            .supports_mnemonic("65c02", None, "bra")
            .expect("resolve bra for 65c02"));
    }
}
