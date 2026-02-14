// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Build opThread hierarchy chunks from the live opForge module registry.

use crate::core::registry::ModuleRegistry;
use crate::opthread::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, HierarchyError, HierarchyPackage,
    ScopedFormDescriptor, ScopedOwner, ScopedRegisterDescriptor,
};
use crate::opthread::package::{encode_hierarchy_chunks, HierarchyChunks, OpcpuCodecError};

/// Errors emitted while building hierarchy package data from registry metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HierarchyBuildError {
    MissingFamilyMetadata { family_id: String },
    MissingCpuMetadata { cpu_id: String },
    Hierarchy(HierarchyError),
    Codec(OpcpuCodecError),
}

impl std::fmt::Display for HierarchyBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFamilyMetadata { family_id } => {
                write!(f, "missing registry metadata for family '{}'", family_id)
            }
            Self::MissingCpuMetadata { cpu_id } => {
                write!(f, "missing registry metadata for cpu '{}'", cpu_id)
            }
            Self::Hierarchy(err) => write!(f, "hierarchy validation error: {}", err),
            Self::Codec(err) => write!(f, "package codec error: {}", err),
        }
    }
}

impl std::error::Error for HierarchyBuildError {}

impl From<HierarchyError> for HierarchyBuildError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

impl From<OpcpuCodecError> for HierarchyBuildError {
    fn from(value: OpcpuCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Build `FAMS`/`CPUS`/`DIAL`/`REGS`/`FORM` chunks from registry metadata.
pub fn build_hierarchy_chunks_from_registry(
    registry: &ModuleRegistry,
) -> Result<HierarchyChunks, HierarchyBuildError> {
    let family_ids = registry.family_ids();

    let mut families = Vec::with_capacity(family_ids.len());
    for family in &family_ids {
        let canonical = registry
            .canonical_dialect_for_family(*family)
            .ok_or_else(|| HierarchyBuildError::MissingFamilyMetadata {
                family_id: family.as_str().to_string(),
            })?;
        families.push(FamilyDescriptor {
            id: family.as_str().to_string(),
            canonical_dialect: canonical.to_string(),
        });
    }

    let cpu_ids = registry.cpu_ids();
    let mut cpus = Vec::with_capacity(cpu_ids.len());
    for cpu in cpu_ids {
        let family_id =
            registry
                .cpu_family_id(cpu)
                .ok_or_else(|| HierarchyBuildError::MissingCpuMetadata {
                    cpu_id: cpu.as_str().to_string(),
                })?;
        let default_dialect = registry.cpu_default_dialect(cpu).map(ToString::to_string);
        cpus.push(CpuDescriptor {
            id: cpu.as_str().to_string(),
            family_id: family_id.as_str().to_string(),
            default_dialect,
        });
    }

    let mut dialects = Vec::new();
    for family in &family_ids {
        let family_id = family.as_str().to_string();
        for dialect in registry.dialect_ids_for_family(*family) {
            dialects.push(DialectDescriptor {
                id: dialect,
                family_id: family_id.clone(),
                cpu_allow_list: None,
            });
        }
    }

    let mut registers = Vec::new();
    for family in &family_ids {
        for register_id in registry.family_register_ids(*family) {
            registers.push(ScopedRegisterDescriptor {
                owner: ScopedOwner::Family(family.as_str().to_string()),
                id: register_id,
            });
        }
    }
    for cpu in registry.cpu_ids() {
        for register_id in registry.cpu_register_ids(cpu) {
            registers.push(ScopedRegisterDescriptor {
                owner: ScopedOwner::Cpu(cpu.as_str().to_string()),
                id: register_id,
            });
        }
    }

    let mut forms = Vec::new();
    for family in &family_ids {
        for mnemonic in registry.family_form_mnemonics(*family) {
            forms.push(ScopedFormDescriptor {
                owner: ScopedOwner::Family(family.as_str().to_string()),
                mnemonic,
            });
        }
    }
    for cpu in registry.cpu_ids() {
        for mnemonic in registry.cpu_form_mnemonics(cpu) {
            forms.push(ScopedFormDescriptor {
                owner: ScopedOwner::Cpu(cpu.as_str().to_string()),
                mnemonic,
            });
        }
    }

    // Ensure the materialized metadata is coherent before returning.
    HierarchyPackage::new(families.clone(), cpus.clone(), dialects.clone())?;

    Ok(HierarchyChunks {
        families,
        cpus,
        dialects,
        registers,
        forms,
    })
}

/// Build and encode an `.opcpu` container with hierarchy chunks from registry metadata.
pub fn build_hierarchy_package_from_registry(
    registry: &ModuleRegistry,
) -> Result<Vec<u8>, HierarchyBuildError> {
    let chunks = build_hierarchy_chunks_from_registry(registry)?;
    encode_hierarchy_chunks(
        &chunks.families,
        &chunks.cpus,
        &chunks.dialects,
        &chunks.registers,
        &chunks.forms,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::ModuleRegistry;
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::i8085::module::I8085CpuModule;
    use crate::m65816::module::M65816CpuModule;
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::package::load_hierarchy_package;
    use crate::z80::module::Z80CpuModule;

    fn test_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        registry
    }

    #[test]
    fn builder_emits_expected_hierarchy_shape() {
        let registry = test_registry();
        let chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("builder should succeed");

        assert_eq!(chunks.families.len(), 2);
        assert_eq!(chunks.cpus.len(), 5);
        assert_eq!(chunks.dialects.len(), 3);
        assert!(chunks.registers.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "intel8080")
                && entry.id == "A"
        }));
        assert!(chunks.registers.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80") && entry.id == "IX"
        }));
        assert!(chunks.forms.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "intel8080")
                && entry.mnemonic == "mov"
        }));
        assert!(chunks.forms.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "djnz"
        }));

        assert!(chunks
            .families
            .iter()
            .any(|fam| fam.id == "intel8080" && fam.canonical_dialect == "intel8080"));
        assert!(chunks
            .families
            .iter()
            .any(|fam| fam.id == "mos6502" && fam.canonical_dialect == "transparent"));
    }

    #[test]
    fn builder_package_round_trip_loads_and_resolves() {
        let registry = test_registry();
        let bytes =
            build_hierarchy_package_from_registry(&registry).expect("encoded package build failed");

        let package = load_hierarchy_package(&bytes).expect("package load should succeed");

        let z80 = package
            .resolve_pipeline("z80", None)
            .expect("z80 pipeline should resolve");
        assert_eq!(z80.family_id, "intel8080");
        assert_eq!(z80.dialect_id, "zilog");

        let c02 = package
            .resolve_pipeline("65c02", None)
            .expect("65c02 pipeline should resolve");
        assert_eq!(c02.family_id, "mos6502");
        assert_eq!(c02.dialect_id, "transparent");
    }

    #[test]
    fn builder_encoding_is_deterministic() {
        let registry = test_registry();
        let a = build_hierarchy_package_from_registry(&registry).expect("first build failed");
        let b = build_hierarchy_package_from_registry(&registry).expect("second build failed");
        assert_eq!(a, b);
    }
}
